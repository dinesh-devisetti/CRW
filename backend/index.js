const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const db = require('./db');
const { connectRedis, redisUtils } = require('./redis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // Allow all origins for dev
  },
});

// CORS configuration
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware optimizations
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize Redis connection
connectRedis();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists in Redis cache first
    let user = await redisUtils.get(`user:${decoded.userId}`);
    
    if (!user) {
      // If not in cache, get from database
      const result = await db.query('SELECT id, username, email FROM users WHERE id = $1', [decoded.userId]);
      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      user = result.rows[0];
      
      // Cache user for 1 hour
      await redisUtils.setex(`user:${user.id}`, 3600, user);
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Authentication Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  try {
    // Check if user already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await db.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Cache user
    await redisUtils.setex(`user:${user.id}`, 3600, user);

    res.status(201).json({
      message: 'User created successfully',
      user: { id: user.id, username: user.username, email: user.email },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Get user from database
    const result = await db.query(
      'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Cache user
    await redisUtils.setex(`user:${user.id}`, 3600, {
      id: user.id,
      username: user.username,
      email: user.email
    });

    res.json({
      message: 'Login successful',
      user: { id: user.id, username: user.username, email: user.email },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { username, email } = req.body;
  
  try {
    // Check if username or email already exists (excluding current user)
    if (username || email) {
      const existingUser = await db.query(
        'SELECT id FROM users WHERE (username = $1 OR email = $2) AND id != $3',
        [username, email, req.user.id]
      );

      if (existingUser.rows.length > 0) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
    }

    // Update user profile
    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;

    if (username) {
      updateFields.push(`username = $${paramCount}`);
      updateValues.push(username);
      paramCount++;
    }

    if (email) {
      updateFields.push(`email = $${paramCount}`);
      updateValues.push(email);
      paramCount++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updateValues.push(req.user.id);
    const query = `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramCount} RETURNING id, username, email, created_at`;
    
    const result = await db.query(query, updateValues);
    const updatedUser = result.rows[0];

    // Update cache
    await redisUtils.setex(`user:${updatedUser.id}`, 3600, updatedUser);

    res.json({ 
      message: 'Profile updated successfully', 
      user: updatedUser 
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Tasks CRUD REST APIs

// Create Task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { title, description, assigned_to, status } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO tasks (title, description, assigned_to, status)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [title, description, assigned_to, status || 'pending']
    );
    const newTask = result.rows[0];

    // Emit real-time event
    io.emit('taskCreated', newTask);

    res.status(201).json(newTask);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// Get all tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM tasks ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Get single task
app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM tasks WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch task' });
  }
});

// Update task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { title, description, assigned_to, status } = req.body;
  try {
    const result = await db.query(
      `UPDATE tasks SET title = $1, description = $2, assigned_to = $3, status = $4 WHERE id = $5 RETURNING *`,
      [title, description, assigned_to, status, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found' });

    const updatedTask = result.rows[0];
    io.emit('taskUpdated', updatedTask);

    res.json(updatedTask);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('DELETE FROM tasks WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found' });

    io.emit('taskDeleted', { id: req.params.id });

    res.json({ message: 'Task deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// Document Management APIs

// Create Document
app.post('/api/documents', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO documents (title, content, created_by) 
       VALUES ($1, $2, $3) RETURNING *`,
      [title, content || '', req.user.id]
    );
    
    const newDocument = result.rows[0];
    
    // Add creator as admin collaborator
    await db.query(
      `INSERT INTO document_collaborators (document_id, user_id, permission) 
       VALUES ($1, $2, 'admin')`,
      [newDocument.id, req.user.id]
    );

    // Emit real-time event
    io.emit('documentCreated', newDocument);

    res.status(201).json(newDocument);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create document' });
  }
});

// Get all documents for user
app.get('/api/documents', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT d.*, dc.permission 
       FROM documents d
       JOIN document_collaborators dc ON d.id = dc.document_id
       WHERE dc.user_id = $1
       ORDER BY d.updated_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
});

// Get single document
app.get('/api/documents/:id', authenticateToken, async (req, res) => {
  try {
    // Check if user has access to document
    const accessResult = await db.query(
      `SELECT dc.permission 
       FROM document_collaborators dc 
       WHERE dc.document_id = $1 AND dc.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (accessResult.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await db.query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });
    
    const document = result.rows[0];
    document.permission = accessResult.rows[0].permission;
    
    res.json(document);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch document' });
  }
});

// Update document content
app.put('/api/documents/:id', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  try {
    // Check if user has write access
    const accessResult = await db.query(
      `SELECT dc.permission 
       FROM document_collaborators dc 
       WHERE dc.document_id = $1 AND dc.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (accessResult.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const permission = accessResult.rows[0].permission;
    if (permission === 'read') {
      return res.status(403).json({ error: 'Read-only access' });
    }

    const result = await db.query(
      `UPDATE documents SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $3 RETURNING *`,
      [title, content, req.params.id]
    );
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const updatedDocument = result.rows[0];
    
    // Emit real-time update
    io.emit('documentUpdated', { 
      id: updatedDocument.id, 
      title: updatedDocument.title, 
      content: updatedDocument.content,
      updated_at: updatedDocument.updated_at
    });

    res.json(updatedDocument);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update document' });
  }
});

// Add collaborator to document
app.post('/api/documents/:id/collaborators', authenticateToken, async (req, res) => {
  const { user_id, permission } = req.body;
  try {
    // Check if current user is admin
    const accessResult = await db.query(
      `SELECT dc.permission 
       FROM document_collaborators dc 
       WHERE dc.document_id = $1 AND dc.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (accessResult.rows.length === 0 || accessResult.rows[0].permission !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await db.query(
      `INSERT INTO document_collaborators (document_id, user_id, permission) 
       VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, user_id, permission || 'read']
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add collaborator' });
  }
});

// Video Calling APIs

// Create video session
app.post('/api/video/sessions', authenticateToken, async (req, res) => {
  const { title } = req.body;
  try {
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const result = await db.query(
      `INSERT INTO video_sessions (session_id, created_by, title) 
       VALUES ($1, $2, $3) RETURNING *`,
      [sessionId, req.user.id, title || 'Video Call']
    );

    const newSession = result.rows[0];
    
    // Emit real-time event
    io.emit('videoSessionCreated', newSession);

    res.status(201).json(newSession);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create video session' });
  }
});

// Get video sessions
app.get('/api/video/sessions', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT vs.*, u.username as creator_name 
       FROM video_sessions vs
       JOIN users u ON vs.created_by = u.id
       WHERE vs.is_active = true
       ORDER BY vs.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch video sessions' });
  }
});

// Join video session
app.post('/api/video/sessions/:sessionId/join', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  try {
    // Check if session exists and is active
    const sessionResult = await db.query(
      'SELECT * FROM video_sessions WHERE session_id = $1 AND is_active = true',
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video session not found or inactive' });
    }

    // Add participant
    await db.query(
      `INSERT INTO video_participants (session_id, user_id) 
       VALUES ((SELECT id FROM video_sessions WHERE session_id = $1), $2)
       ON CONFLICT (session_id, user_id) DO NOTHING`,
      [sessionId, req.user.id]
    );

    // Emit real-time event
    io.emit('userJoinedVideo', { 
      sessionId, 
      userId: req.user.id, 
      username: req.user.username 
    });

    res.json({ message: 'Joined video session successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to join video session' });
  }
});

// Leave video session
app.post('/api/video/sessions/:sessionId/leave', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  try {
    await db.query(
      `UPDATE video_participants 
       SET left_at = CURRENT_TIMESTAMP 
       WHERE session_id = (SELECT id FROM video_sessions WHERE session_id = $1) 
       AND user_id = $2`,
      [sessionId, req.user.id]
    );

    // Emit real-time event
    io.emit('userLeftVideo', { 
      sessionId, 
      userId: req.user.id, 
      username: req.user.username 
    });

    res.json({ message: 'Left video session successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to leave video session' });
  }
});

// End video session
app.post('/api/video/sessions/:sessionId/end', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  try {
    // Check if user is the creator
    const sessionResult = await db.query(
      'SELECT * FROM video_sessions WHERE session_id = $1 AND created_by = $2',
      [sessionId, req.user.id]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(403).json({ error: 'Only session creator can end the session' });
    }

    await db.query(
      'UPDATE video_sessions SET is_active = false, ended_at = CURRENT_TIMESTAMP WHERE session_id = $1',
      [sessionId]
    );

    // Emit real-time event
    io.emit('videoSessionEnded', { sessionId });

    res.json({ message: 'Video session ended successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to end video session' });
  }
});

// Repository Management APIs

// Create repository
app.post('/api/repositories', authenticateToken, async (req, res) => {
  const { name, description, isPrivate } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO repositories (name, description, owner_id, is_private) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [name, description, req.user.id, isPrivate || false]
    );

    const newRepo = result.rows[0];
    
    // Create default main branch
    await db.query(
      `INSERT INTO branches (repository_id, name, is_default, created_by) 
       VALUES ($1, 'main', true, $2)`,
      [newRepo.id, req.user.id]
    );

    // Emit real-time event
    io.emit('repositoryCreated', newRepo);

    res.status(201).json(newRepo);
  } catch (err) {
    if (err.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'Repository name already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Failed to create repository' });
    }
  }
});

// Get user repositories
app.get('/api/repositories', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT r.*, u.username as owner_name,
              (SELECT COUNT(*) FROM repository_collaborators rc WHERE rc.repository_id = r.id) as collaborator_count
       FROM repositories r
       JOIN users u ON r.owner_id = u.id
       WHERE r.owner_id = $1 OR r.id IN (
         SELECT repository_id FROM repository_collaborators WHERE user_id = $1
       )
       ORDER BY r.updated_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch repositories' });
  }
});

// Get repository details
app.get('/api/repositories/:id', authenticateToken, async (req, res) => {
  try {
    const repoResult = await db.query(
      `SELECT r.*, u.username as owner_name
       FROM repositories r
       JOIN users u ON r.owner_id = u.id
       WHERE r.id = $1`,
      [req.params.id]
    );

    if (repoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const repo = repoResult.rows[0];

    // Check access permissions
    const accessResult = await db.query(
      `SELECT permission FROM repository_collaborators 
       WHERE repository_id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );

    const isOwner = repo.owner_id === req.user.id;
    const hasAccess = isOwner || accessResult.rows.length > 0;

    if (!hasAccess && repo.is_private) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get branches
    const branchesResult = await db.query(
      `SELECT b.*, u.username as creator_name
       FROM branches b
       LEFT JOIN users u ON b.created_by = u.id
       WHERE b.repository_id = $1
       ORDER BY b.is_default DESC, b.created_at ASC`,
      [req.params.id]
    );

    // Get collaborators
    const collaboratorsResult = await db.query(
      `SELECT rc.*, u.username, u.email
       FROM repository_collaborators rc
       JOIN users u ON rc.user_id = u.id
       WHERE rc.repository_id = $1`,
      [req.params.id]
    );

    res.json({
      ...repo,
      branches: branchesResult.rows,
      collaborators: collaboratorsResult.rows,
      userPermission: isOwner ? 'admin' : (accessResult.rows[0]?.permission || 'read')
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch repository' });
  }
});

// Create branch
app.post('/api/repositories/:id/branches', authenticateToken, async (req, res) => {
  const { name } = req.body;
  try {
    // Check write permissions
    const repoResult = await db.query(
      'SELECT owner_id, is_private FROM repositories WHERE id = $1',
      [req.params.id]
    );

    if (repoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const repo = repoResult.rows[0];
    const isOwner = repo.owner_id === req.user.id;
    
    if (!isOwner) {
      const accessResult = await db.query(
        `SELECT permission FROM repository_collaborators 
         WHERE repository_id = $1 AND user_id = $2 AND permission IN ('write', 'admin')`,
        [req.params.id, req.user.id]
      );

      if (accessResult.rows.length === 0) {
        return res.status(403).json({ error: 'Write access required' });
      }
    }

    const result = await db.query(
      `INSERT INTO branches (repository_id, name, created_by) 
       VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, name, req.user.id]
    );

    const newBranch = result.rows[0];

    // Emit real-time event
    io.emit('branchCreated', { repositoryId: req.params.id, branch: newBranch });

    res.status(201).json(newBranch);
  } catch (err) {
    if (err.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'Branch name already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Failed to create branch' });
    }
  }
});

// Get repository files
app.get('/api/repositories/:id/files', authenticateToken, async (req, res) => {
  const { branch = 'main' } = req.query;
  try {
    // Get latest commit for branch
    const commitResult = await db.query(
      `SELECT c.id, c.commit_hash FROM commits c
       JOIN branches b ON c.branch_id = b.id
       WHERE b.repository_id = $1 AND b.name = $2
       ORDER BY c.created_at DESC LIMIT 1`,
      [req.params.id, branch]
    );

    if (commitResult.rows.length === 0) {
      return res.json([]);
    }

    const commit = commitResult.rows[0];

    // Get files for this commit
    const filesResult = await db.query(
      `SELECT file_path, content, file_type, size_bytes
       FROM files
       WHERE repository_id = $1 AND commit_id = $2
       ORDER BY file_path`,
      [req.params.id, commit.id]
    );

    res.json(filesResult.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// Create/Update file
app.post('/api/repositories/:id/files', authenticateToken, async (req, res) => {
  const { filePath, content, commitMessage, branch = 'main' } = req.body;
  try {
    // Check write permissions
    const repoResult = await db.query(
      'SELECT owner_id FROM repositories WHERE id = $1',
      [req.params.id]
    );

    if (repoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const isOwner = repoResult.rows[0].owner_id === req.user.id;
    
    if (!isOwner) {
      const accessResult = await db.query(
        `SELECT permission FROM repository_collaborators 
         WHERE repository_id = $1 AND user_id = $2 AND permission IN ('write', 'admin')`,
        [req.params.id, req.user.id]
      );

      if (accessResult.rows.length === 0) {
        return res.status(403).json({ error: 'Write access required' });
      }
    }

    // Get branch
    const branchResult = await db.query(
      'SELECT id FROM branches WHERE repository_id = $1 AND name = $2',
      [req.params.id, branch]
    );

    if (branchResult.rows.length === 0) {
      return res.status(404).json({ error: 'Branch not found' });
    }

    const branchId = branchResult.rows[0].id;

    // Create commit
    const commitHash = require('crypto').createHash('sha1')
      .update(content + Date.now().toString())
      .digest('hex')
      .substring(0, 40);

    const commitResult = await db.query(
      `INSERT INTO commits (repository_id, branch_id, commit_hash, message, author_id) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.params.id, branchId, commitHash, commitMessage, req.user.id]
    );

    const commit = commitResult.rows[0];

    // Create/Update file
    await db.query(
      `INSERT INTO files (repository_id, commit_id, file_path, content, file_type, size_bytes)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (repository_id, commit_id, file_path) 
       DO UPDATE SET content = $4, file_type = $5, size_bytes = $6`,
      [
        req.params.id, 
        commit.id, 
        filePath, 
        content, 
        filePath.split('.').pop() || 'txt',
        Buffer.byteLength(content, 'utf8')
      ]
    );

    // Update repository updated_at
    await db.query(
      'UPDATE repositories SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
      [req.params.id]
    );

    // Emit real-time event
    io.emit('fileUpdated', { 
      repositoryId: req.params.id, 
      filePath, 
      commit: commit,
      branch: branch
    });

    res.status(201).json({ 
      message: 'File updated successfully', 
      commit: commit 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update file' });
  }
});

// Add collaborator
app.post('/api/repositories/:id/collaborators', authenticateToken, async (req, res) => {
  const { username, permission = 'read' } = req.body;
  try {
    // Check if user is owner or admin
    const repoResult = await db.query(
      'SELECT owner_id FROM repositories WHERE id = $1',
      [req.params.id]
    );

    if (repoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const isOwner = repoResult.rows[0].owner_id === req.user.id;
    
    if (!isOwner) {
      const accessResult = await db.query(
        `SELECT permission FROM repository_collaborators 
         WHERE repository_id = $1 AND user_id = $2 AND permission = 'admin'`,
        [req.params.id, req.user.id]
      );

      if (accessResult.rows.length === 0) {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }

    // Find user by username
    const userResult = await db.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const collaboratorId = userResult.rows[0].id;

    // Add collaborator
    const result = await db.query(
      `INSERT INTO repository_collaborators (repository_id, user_id, permission) 
       VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, collaboratorId, permission]
    );

    const newCollaborator = result.rows[0];

    // Emit real-time event
    io.emit('collaboratorAdded', { 
      repositoryId: req.params.id, 
      collaborator: newCollaborator 
    });

    res.status(201).json(newCollaborator);
  } catch (err) {
    if (err.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'User is already a collaborator' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Failed to add collaborator' });
    }
  }
});

// Pull Request APIs

// Create pull request
app.post('/api/repositories/:id/pull-requests', authenticateToken, async (req, res) => {
  const { title, description, sourceBranch, targetBranch } = req.body;
  try {
    // Get branch IDs
    const sourceBranchResult = await db.query(
      'SELECT id FROM branches WHERE repository_id = $1 AND name = $2',
      [req.params.id, sourceBranch]
    );

    const targetBranchResult = await db.query(
      'SELECT id FROM branches WHERE repository_id = $1 AND name = $2',
      [req.params.id, targetBranch]
    );

    if (sourceBranchResult.rows.length === 0 || targetBranchResult.rows.length === 0) {
      return res.status(404).json({ error: 'Branch not found' });
    }

    const result = await db.query(
      `INSERT INTO pull_requests (repository_id, title, description, source_branch_id, target_branch_id, author_id) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.params.id, title, description, sourceBranchResult.rows[0].id, targetBranchResult.rows[0].id, req.user.id]
    );

    const newPR = result.rows[0];

    // Emit real-time event
    io.emit('pullRequestCreated', { repositoryId: req.params.id, pullRequest: newPR });

    res.status(201).json(newPR);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create pull request' });
  }
});

// Get pull requests for repository
app.get('/api/repositories/:id/pull-requests', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT pr.*, 
              u.username as author_name,
              sb.name as source_branch_name,
              tb.name as target_branch_name
       FROM pull_requests pr
       JOIN users u ON pr.author_id = u.id
       JOIN branches sb ON pr.source_branch_id = sb.id
       JOIN branches tb ON pr.target_branch_id = tb.id
       WHERE pr.repository_id = $1
       ORDER BY pr.created_at DESC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch pull requests' });
  }
});

// Get pull request details
app.get('/api/pull-requests/:id', authenticateToken, async (req, res) => {
  try {
    const prResult = await db.query(
      `SELECT pr.*, 
              u.username as author_name,
              sb.name as source_branch_name,
              tb.name as target_branch_name,
              r.name as repository_name
       FROM pull_requests pr
       JOIN users u ON pr.author_id = u.id
       JOIN branches sb ON pr.source_branch_id = sb.id
       JOIN branches tb ON pr.target_branch_id = tb.id
       JOIN repositories r ON pr.repository_id = r.id
       WHERE pr.id = $1`,
      [req.params.id]
    );

    if (prResult.rows.length === 0) {
      return res.status(404).json({ error: 'Pull request not found' });
    }

    const pr = prResult.rows[0];

    // Get reviews
    const reviewsResult = await db.query(
      `SELECT prr.*, u.username as reviewer_name
       FROM pull_request_reviews prr
       JOIN users u ON prr.reviewer_id = u.id
       WHERE prr.pull_request_id = $1
       ORDER BY prr.created_at DESC`,
      [req.params.id]
    );

    // Get comments
    const commentsResult = await db.query(
      `SELECT prc.*, u.username as author_name
       FROM pull_request_comments prc
       JOIN users u ON prc.author_id = u.id
       WHERE prc.pull_request_id = $1
       ORDER BY prc.created_at ASC`,
      [req.params.id]
    );

    res.json({
      ...pr,
      reviews: reviewsResult.rows,
      comments: commentsResult.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch pull request' });
  }
});

// Add review to pull request
app.post('/api/pull-requests/:id/reviews', authenticateToken, async (req, res) => {
  const { status, comment } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO pull_request_reviews (pull_request_id, reviewer_id, status, comment) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [req.params.id, req.user.id, status, comment]
    );

    const newReview = result.rows[0];

    // Emit real-time event
    io.emit('pullRequestReviewAdded', { 
      pullRequestId: req.params.id, 
      review: newReview 
    });

    res.status(201).json(newReview);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add review' });
  }
});

// Add comment to pull request
app.post('/api/pull-requests/:id/comments', authenticateToken, async (req, res) => {
  const { filePath, lineNumber, comment } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO pull_request_comments (pull_request_id, file_path, line_number, comment, author_id) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.params.id, filePath, lineNumber, comment, req.user.id]
    );

    const newComment = result.rows[0];

    // Emit real-time event
    io.emit('pullRequestCommentAdded', { 
      pullRequestId: req.params.id, 
      comment: newComment 
    });

    res.status(201).json(newComment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Merge pull request
app.post('/api/pull-requests/:id/merge', authenticateToken, async (req, res) => {
  try {
    // Get pull request details
    const prResult = await db.query(
      `SELECT pr.*, r.owner_id as repo_owner_id
       FROM pull_requests pr
       JOIN repositories r ON pr.repository_id = r.id
       WHERE pr.id = $1`,
      [req.params.id]
    );

    if (prResult.rows.length === 0) {
      return res.status(404).json({ error: 'Pull request not found' });
    }

    const pr = prResult.rows[0];

    // Check permissions (owner or admin collaborator)
    const isOwner = pr.repo_owner_id === req.user.id;
    
    if (!isOwner) {
      const accessResult = await db.query(
        `SELECT permission FROM repository_collaborators 
         WHERE repository_id = $1 AND user_id = $2 AND permission = 'admin'`,
        [pr.repository_id, req.user.id]
      );

      if (accessResult.rows.length === 0) {
        return res.status(403).json({ error: 'Admin access required to merge' });
      }
    }

    // Update pull request status
    await db.query(
      `UPDATE pull_requests 
       SET status = 'merged', merged_at = CURRENT_TIMESTAMP, merged_by = $1
       WHERE id = $2`,
      [req.user.id, req.params.id]
    );

    // Emit real-time event
    io.emit('pullRequestMerged', { 
      pullRequestId: req.params.id, 
      mergedBy: req.user.id 
    });

    res.json({ message: 'Pull request merged successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to merge pull request' });
  }
});

// Jira-like Project Management APIs

// Create project
app.post('/api/projects', authenticateToken, async (req, res) => {
  const { key, name, description, projectType, isPrivate } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO projects (key, name, description, project_type, lead_id, is_private) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [key, name, description, projectType || 'software', req.user.id, isPrivate || false]
    );

    const newProject = result.rows[0];
    
    // Add creator as admin member
    await db.query(
      `INSERT INTO project_members (project_id, user_id, role) 
       VALUES ($1, $2, 'admin')`,
      [newProject.id, req.user.id]
    );

    // Create default workflow
    const workflowResult = await db.query(
      `INSERT INTO workflows (name, description, project_id, is_default) 
       VALUES ($1, $2, $3, true) RETURNING *`,
      ['Default Workflow', 'Default workflow for the project', newProject.id]
    );

    const workflow = workflowResult.rows[0];

    // Create default workflow transitions
    const statuses = await db.query('SELECT * FROM statuses ORDER BY id');
    for (let i = 0; i < statuses.rows.length - 1; i++) {
      await db.query(
        `INSERT INTO workflow_transitions (workflow_id, from_status_id, to_status_id, name) 
         VALUES ($1, $2, $3, $4)`,
        [workflow.id, statuses.rows[i].id, statuses.rows[i + 1].id, `Move to ${statuses.rows[i + 1].name}`]
      );
    }

    // Emit real-time event
    io.emit('projectCreated', newProject);

    res.status(201).json(newProject);
  } catch (err) {
    if (err.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'Project key already exists' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Failed to create project' });
    }
  }
});

// Get user projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, u.username as lead_name,
              (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = p.id) as member_count,
              (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id) as issue_count
       FROM projects p
       JOIN users u ON p.lead_id = u.id
       WHERE p.lead_id = $1 OR p.id IN (
         SELECT project_id FROM project_members WHERE user_id = $1
       )
       ORDER BY p.updated_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// Get project details
app.get('/api/projects/:id', authenticateToken, async (req, res) => {
  try {
    const projectResult = await db.query(
      `SELECT p.*, u.username as lead_name
       FROM projects p
       JOIN users u ON p.lead_id = u.id
       WHERE p.id = $1`,
      [req.params.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];

    // Check access permissions
    const accessResult = await db.query(
      `SELECT role FROM project_members 
       WHERE project_id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );

    const isLead = project.lead_id === req.user.id;
    const hasAccess = isLead || accessResult.rows.length > 0;

    if (!hasAccess && project.is_private) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get members (including project lead)
    const membersResult = await db.query(
      `SELECT DISTINCT u.id as user_id, u.username, u.email, 
              COALESCE(pm.role, CASE WHEN u.id = $2 THEN 'admin' ELSE 'viewer' END) as role
       FROM users u
       LEFT JOIN project_members pm ON u.id = pm.user_id AND pm.project_id = $1
       WHERE u.id = $2 OR pm.user_id IS NOT NULL
       ORDER BY u.username`,
      [req.params.id, req.user.id]
    );

    // Get recent issues
    const issuesResult = await db.query(
      `SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
              p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
              s.name as status_name, s.color as status_color,
              u1.username as reporter_name, u2.username as assignee_name
       FROM issues i
       LEFT JOIN issue_types it ON i.issue_type_id = it.id
       LEFT JOIN priorities p ON i.priority_id = p.id
       LEFT JOIN statuses s ON i.status_id = s.id
       LEFT JOIN users u1 ON i.reporter_id = u1.id
       LEFT JOIN users u2 ON i.assignee_id = u2.id
       WHERE i.project_id = $1
       ORDER BY i.created_at DESC
       LIMIT 10`,
      [req.params.id]
    );

    res.json({
      ...project,
      members: membersResult.rows,
      recentIssues: issuesResult.rows,
      userRole: isLead ? 'admin' : (accessResult.rows[0]?.role || 'viewer')
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// Create issue
app.post('/api/projects/:id/issues', authenticateToken, async (req, res) => {
  const { issueTypeId, priorityId, summary, description, assigneeId, storyPoints, timeEstimate, dueDate } = req.body;
  try {
    // Check project access
    const projectResult = await db.query(
      'SELECT key FROM projects WHERE id = $1',
      [req.params.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];

    // Generate issue key
    const issueCountResult = await db.query(
      'SELECT COUNT(*) as count FROM issues WHERE project_id = $1',
      [req.params.id]
    );
    const issueNumber = parseInt(issueCountResult.rows[0].count) + 1;
    const issueKey = `${project.key}-${issueNumber}`;

    // Get default status (To Do)
    const statusResult = await db.query(
      "SELECT id FROM statuses WHERE name = 'To Do' LIMIT 1"
    );
    const defaultStatusId = statusResult.rows[0].id;

    const result = await db.query(
      `INSERT INTO issues (key, project_id, issue_type_id, priority_id, status_id, summary, description, reporter_id, assignee_id, story_points, time_estimate, due_date) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [issueKey, req.params.id, issueTypeId, priorityId, defaultStatusId, summary, description, req.user.id, assigneeId, storyPoints, timeEstimate, dueDate]
    );

    const newIssue = result.rows[0];

    // Add reporter as watcher
    await db.query(
      `INSERT INTO issue_watchers (issue_id, user_id) VALUES ($1, $2)`,
      [newIssue.id, req.user.id]
    );

    // Emit real-time event
    io.emit('issueCreated', { projectId: req.params.id, issue: newIssue });

    res.status(201).json(newIssue);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create issue' });
  }
});

// Get project issues
app.get('/api/projects/:id/issues', authenticateToken, async (req, res) => {
  const { status, assignee, issueType, priority, search } = req.query;
  try {
    let query = `
      SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
             p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
             s.name as status_name, s.color as status_color,
             u1.username as reporter_name, u2.username as assignee_name
      FROM issues i
      LEFT JOIN issue_types it ON i.issue_type_id = it.id
      LEFT JOIN priorities p ON i.priority_id = p.id
      LEFT JOIN statuses s ON i.status_id = s.id
      LEFT JOIN users u1 ON i.reporter_id = u1.id
      LEFT JOIN users u2 ON i.assignee_id = u2.id
      WHERE i.project_id = $1
    `;
    
    const params = [req.params.id];
    let paramCount = 1;

    if (status) {
      paramCount++;
      query += ` AND s.name = $${paramCount}`;
      params.push(status);
    }

    if (assignee) {
      paramCount++;
      query += ` AND u2.username = $${paramCount}`;
      params.push(assignee);
    }

    if (issueType) {
      paramCount++;
      query += ` AND it.name = $${paramCount}`;
      params.push(issueType);
    }

    if (priority) {
      paramCount++;
      query += ` AND p.name = $${paramCount}`;
      params.push(priority);
    }

    if (search) {
      paramCount++;
      query += ` AND (i.summary ILIKE $${paramCount} OR i.description ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY i.created_at DESC`;

    const result = await db.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch issues' });
  }
});

// Get issue details
app.get('/api/issues/:id', authenticateToken, async (req, res) => {
  try {
    const issueResult = await db.query(
      `SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
              p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
              s.name as status_name, s.color as status_color,
              u1.username as reporter_name, u2.username as assignee_name,
              proj.name as project_name, proj.key as project_key
       FROM issues i
       LEFT JOIN issue_types it ON i.issue_type_id = it.id
       LEFT JOIN priorities p ON i.priority_id = p.id
       LEFT JOIN statuses s ON i.status_id = s.id
       LEFT JOIN users u1 ON i.reporter_id = u1.id
       LEFT JOIN users u2 ON i.assignee_id = u2.id
       LEFT JOIN projects proj ON i.project_id = proj.id
       WHERE i.id = $1`,
      [req.params.id]
    );

    if (issueResult.rows.length === 0) {
      return res.status(404).json({ error: 'Issue not found' });
    }

    const issue = issueResult.rows[0];

    // Get comments
    const commentsResult = await db.query(
      `SELECT ic.*, u.username as author_name
       FROM issue_comments ic
       JOIN users u ON ic.author_id = u.id
       WHERE ic.issue_id = $1
       ORDER BY ic.created_at ASC`,
      [req.params.id]
    );

    // Get watchers
    const watchersResult = await db.query(
      `SELECT iw.*, u.username
       FROM issue_watchers iw
       JOIN users u ON iw.user_id = u.id
       WHERE iw.issue_id = $1`,
      [req.params.id]
    );

    // Get history
    const historyResult = await db.query(
      `SELECT ih.*, u.username as changed_by_name
       FROM issue_history ih
       LEFT JOIN users u ON ih.changed_by = u.id
       WHERE ih.issue_id = $1
       ORDER BY ih.changed_at DESC`,
      [req.params.id]
    );

    res.json({
      ...issue,
      comments: commentsResult.rows,
      watchers: watchersResult.rows,
      history: historyResult.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch issue' });
  }
});

// Update issue
app.put('/api/issues/:id', authenticateToken, async (req, res) => {
  const { summary, description, assigneeId, statusId, priorityId, storyPoints, timeEstimate, dueDate } = req.body;
  try {
    // Get current issue
    const currentIssueResult = await db.query(
      'SELECT * FROM issues WHERE id = $1',
      [req.params.id]
    );

    if (currentIssueResult.rows.length === 0) {
      return res.status(404).json({ error: 'Issue not found' });
    }

    const currentIssue = currentIssueResult.rows[0];

    // Update issue
    const result = await db.query(
      `UPDATE issues 
       SET summary = COALESCE($1, summary),
           description = COALESCE($2, description),
           assignee_id = COALESCE($3, assignee_id),
           status_id = COALESCE($4, status_id),
           priority_id = COALESCE($5, priority_id),
           story_points = COALESCE($6, story_points),
           time_estimate = COALESCE($7, time_estimate),
           due_date = COALESCE($8, due_date),
           updated_at = CURRENT_TIMESTAMP,
           resolved_at = CASE WHEN $4 IS NOT NULL AND (SELECT is_final FROM statuses WHERE id = $4) THEN CURRENT_TIMESTAMP ELSE resolved_at END
       WHERE id = $9 RETURNING *`,
      [summary, description, assigneeId, statusId, priorityId, storyPoints, timeEstimate, dueDate, req.params.id]
    );

    const updatedIssue = result.rows[0];

    // Log changes in history
    const changes = [
      { field: 'summary', old: currentIssue.summary, new: summary },
      { field: 'description', old: currentIssue.description, new: description },
      { field: 'assignee_id', old: currentIssue.assignee_id, new: assigneeId },
      { field: 'status_id', old: currentIssue.status_id, new: statusId },
      { field: 'priority_id', old: currentIssue.priority_id, new: priorityId },
      { field: 'story_points', old: currentIssue.story_points, new: storyPoints },
      { field: 'time_estimate', old: currentIssue.time_estimate, new: timeEstimate },
      { field: 'due_date', old: currentIssue.due_date, new: dueDate }
    ];

    for (const change of changes) {
      if (change.new !== null && change.new !== change.old) {
        await db.query(
          `INSERT INTO issue_history (issue_id, field_name, old_value, new_value, changed_by) 
           VALUES ($1, $2, $3, $4, $5)`,
          [req.params.id, change.field, change.old?.toString() || '', change.new?.toString() || '', req.user.id]
        );
      }
    }

    // Emit real-time event
    io.emit('issueUpdated', { issueId: req.params.id, issue: updatedIssue });

    res.json(updatedIssue);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update issue' });
  }
});

// Add comment to issue
app.post('/api/issues/:id/comments', authenticateToken, async (req, res) => {
  const { body } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO issue_comments (issue_id, author_id, body) 
       VALUES ($1, $2, $3) RETURNING *`,
      [req.params.id, req.user.id, body]
    );

    const newComment = result.rows[0];

    // Emit real-time event
    io.emit('issueCommentAdded', { issueId: req.params.id, comment: newComment });

    res.status(201).json(newComment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// Get metadata (issue types, priorities, statuses)
app.get('/api/metadata', authenticateToken, async (req, res) => {
  try {
    const [issueTypes, priorities, statuses] = await Promise.all([
      db.query('SELECT * FROM issue_types ORDER BY name'),
      db.query('SELECT * FROM priorities ORDER BY level'),
      db.query('SELECT * FROM statuses ORDER BY id')
    ]);

    res.json({
      issueTypes: issueTypes.rows,
      priorities: priorities.rows,
      statuses: statuses.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch metadata' });
  }
});

// Sprint Management APIs

// Create sprint
app.post('/api/projects/:id/sprints', authenticateToken, async (req, res) => {
  const { name, goal, startDate, endDate } = req.body;
  try {
    // Check project access
    const projectResult = await db.query(
      'SELECT id FROM projects WHERE id = $1',
      [req.params.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const result = await db.query(
      `INSERT INTO sprints (name, project_id, goal, start_date, end_date) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [name, req.params.id, goal, startDate, endDate]
    );

    const newSprint = result.rows[0];

    // Emit real-time event
    io.emit('sprintCreated', { projectId: req.params.id, sprint: newSprint });

    res.status(201).json(newSprint);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create sprint' });
  }
});

// Get project sprints
app.get('/api/projects/:id/sprints', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT s.*, 
              (SELECT COUNT(*) FROM sprint_issues si WHERE si.sprint_id = s.id) as issue_count
       FROM sprints s
       WHERE s.project_id = $1
       ORDER BY s.created_at DESC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sprints' });
  }
});

// Update sprint
app.put('/api/sprints/:id', authenticateToken, async (req, res) => {
  const { name, goal, startDate, endDate, state } = req.body;
  try {
    const result = await db.query(
      `UPDATE sprints 
       SET name = COALESCE($1, name),
           goal = COALESCE($2, goal),
           start_date = COALESCE($3, start_date),
           end_date = COALESCE($4, end_date),
           state = COALESCE($5, state)
       WHERE id = $6 RETURNING *`,
      [name, goal, startDate, endDate, state, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sprint not found' });
    }

    const updatedSprint = result.rows[0];

    // Emit real-time event
    io.emit('sprintUpdated', { sprintId: req.params.id, sprint: updatedSprint });

    res.json(updatedSprint);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update sprint' });
  }
});

// Add issue to sprint
app.post('/api/sprints/:id/issues', authenticateToken, async (req, res) => {
  const { issueId } = req.body;
  try {
    const result = await db.query(
      `INSERT INTO sprint_issues (sprint_id, issue_id) 
       VALUES ($1, $2) RETURNING *`,
      [req.params.id, issueId]
    );

    const newSprintIssue = result.rows[0];

    // Emit real-time event
    io.emit('issueAddedToSprint', { sprintId: req.params.id, issueId, sprintIssue: newSprintIssue });

    res.status(201).json(newSprintIssue);
  } catch (err) {
    if (err.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'Issue is already in this sprint' });
    } else {
      console.error(err);
      res.status(500).json({ error: 'Failed to add issue to sprint' });
    }
  }
});

// Remove issue from sprint
app.delete('/api/sprints/:id/issues/:issueId', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `DELETE FROM sprint_issues 
       WHERE sprint_id = $1 AND issue_id = $2 RETURNING *`,
      [req.params.id, req.params.issueId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Issue not found in sprint' });
    }

    // Emit real-time event
    io.emit('issueRemovedFromSprint', { sprintId: req.params.id, issueId: req.params.issueId });

    res.json({ message: 'Issue removed from sprint successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to remove issue from sprint' });
  }
});

// Get sprint issues
app.get('/api/sprints/:id/issues', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
              p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
              s.name as status_name, s.color as status_color,
              u1.username as reporter_name, u2.username as assignee_name
       FROM sprint_issues si
       JOIN issues i ON si.issue_id = i.id
       LEFT JOIN issue_types it ON i.issue_type_id = it.id
       LEFT JOIN priorities p ON i.priority_id = p.id
       LEFT JOIN statuses s ON i.status_id = s.id
       LEFT JOIN users u1 ON i.reporter_id = u1.id
       LEFT JOIN users u2 ON i.assignee_id = u2.id
       WHERE si.sprint_id = $1
       ORDER BY i.created_at ASC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sprint issues' });
  }
});

// Get issues assigned to current user
app.get('/api/my-issues', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
              p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
              s.name as status_name, s.color as status_color,
              u1.username as reporter_name, u2.username as assignee_name,
              proj.name as project_name, proj.key as project_key
       FROM issues i
       LEFT JOIN issue_types it ON i.issue_type_id = it.id
       LEFT JOIN priorities p ON i.priority_id = p.id
       LEFT JOIN statuses s ON i.status_id = s.id
       LEFT JOIN users u1 ON i.reporter_id = u1.id
       LEFT JOIN users u2 ON i.assignee_id = u2.id
       LEFT JOIN projects proj ON i.project_id = proj.id
       WHERE i.assignee_id = $1
       ORDER BY 
         CASE s.name 
           WHEN 'In Progress' THEN 1
           WHEN 'To Do' THEN 2
           WHEN 'Done' THEN 3
           WHEN 'Closed' THEN 4
           ELSE 5
         END,
         p.level ASC,
         i.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch assigned issues' });
  }
});

// Get issues reported by current user
app.get('/api/my-reported-issues', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT i.*, it.name as issue_type_name, it.icon as issue_type_icon, it.color as issue_type_color,
              p.name as priority_name, p.icon as priority_icon, p.color as priority_color,
              s.name as status_name, s.color as status_color,
              u1.username as reporter_name, u2.username as assignee_name,
              proj.name as project_name, proj.key as project_key
       FROM issues i
       LEFT JOIN issue_types it ON i.issue_type_id = it.id
       LEFT JOIN priorities p ON i.priority_id = p.id
       LEFT JOIN statuses s ON i.status_id = s.id
       LEFT JOIN users u1 ON i.reporter_id = u1.id
       LEFT JOIN users u2 ON i.assignee_id = u2.id
       LEFT JOIN projects proj ON i.project_id = proj.id
       WHERE i.reporter_id = $1
       ORDER BY i.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch reported issues' });
  }
});

// Get all users for assignee dropdown
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, username, email FROM users ORDER BY username'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ==================== TEAMS APIs ====================

// Create a new team
app.post('/api/teams', authenticateToken, async (req, res) => {
  try {
    const { name, description, is_private } = req.body;
    
    const result = await db.query(
      'INSERT INTO teams (name, description, owner_id, is_private) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, description, req.user.id, is_private || false]
    );
    
    const team = result.rows[0];
    
    // Add owner as team member
    await db.query(
      'INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)',
      [team.id, req.user.id, 'owner']
    );
    
    // Create general channel
    await db.query(
      'INSERT INTO channels (team_id, name, description, created_by) VALUES ($1, $2, $3, $4)',
      [team.id, 'General', 'General discussion channel', req.user.id]
    );
    
    res.status(201).json(team);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create team' });
  }
});

// Get user's teams
app.get('/api/teams', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT t.*, tm.role, u.username as owner_name
       FROM teams t
       JOIN team_members tm ON t.id = tm.team_id
       LEFT JOIN users u ON t.owner_id = u.id
       WHERE tm.user_id = $1
       ORDER BY t.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
});

// Get team details with channels and members
app.get('/api/teams/:id', authenticateToken, async (req, res) => {
  try {
    // Check if user is team member
    const memberCheck = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Get team details
    const teamResult = await db.query(
      `SELECT t.*, u.username as owner_name
       FROM teams t
       LEFT JOIN users u ON t.owner_id = u.id
       WHERE t.id = $1`,
      [req.params.id]
    );
    
    if (teamResult.rows.length === 0) {
      return res.status(404).json({ error: 'Team not found' });
    }
    
    const team = teamResult.rows[0];
    
    // Get channels
    const channelsResult = await db.query(
      `SELECT c.*, u.username as created_by_name
       FROM channels c
       LEFT JOIN users u ON c.created_by = u.id
       WHERE c.team_id = $1
       ORDER BY c.created_at ASC`,
      [req.params.id]
    );
    
    // Get team members
    const membersResult = await db.query(
      `SELECT tm.*, u.username, u.email
       FROM team_members tm
       JOIN users u ON tm.user_id = u.id
       WHERE tm.team_id = $1
       ORDER BY tm.role, u.username`,
      [req.params.id]
    );
    
    team.channels = channelsResult.rows;
    team.members = membersResult.rows;
    team.userRole = memberCheck.rows[0].role;
    
    res.json(team);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch team details' });
  }
});

// Create a channel
app.post('/api/teams/:id/channels', authenticateToken, async (req, res) => {
  try {
    const { name, description, is_private } = req.body;
    
    // Check if user is team member
    const memberCheck = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await db.query(
      'INSERT INTO channels (team_id, name, description, is_private, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.params.id, name, description, is_private || false, req.user.id]
    );
    
    const channel = result.rows[0];
    
    // Add creator as channel member
    await db.query(
      'INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2)',
      [channel.id, req.user.id]
    );
    
    res.status(201).json(channel);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create channel' });
  }
});

// Get channel messages
app.get('/api/channels/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    
    // Check if user is channel member
    const memberCheck = await db.query(
      `SELECT cm.* FROM channel_members cm
       JOIN channels c ON cm.channel_id = c.id
       WHERE cm.channel_id = $1 AND cm.user_id = $2`,
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await db.query(
      `SELECT cm.*, u.username, u.email
       FROM chat_messages cm
       JOIN users u ON cm.user_id = u.id
       WHERE cm.channel_id = $1
       ORDER BY cm.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.id, limit, offset]
    );
    
    res.json(result.rows.reverse());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Send message to channel
app.post('/api/channels/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { message, message_type = 'text', reply_to } = req.body;
    
    // Check if user is channel member
    const memberCheck = await db.query(
      `SELECT cm.* FROM channel_members cm
       JOIN channels c ON cm.channel_id = c.id
       WHERE cm.channel_id = $1 AND cm.user_id = $2`,
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await db.query(
      'INSERT INTO chat_messages (channel_id, user_id, message, message_type, reply_to) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.params.id, req.user.id, message, message_type, reply_to]
    );
    
    const newMessage = result.rows[0];
    
    // Get user info for the message
    const userResult = await db.query(
      'SELECT username, email FROM users WHERE id = $1',
      [req.user.id]
    );
    
    newMessage.username = userResult.rows[0].username;
    newMessage.email = userResult.rows[0].email;
    
    // Emit to channel members
    io.to(`channel_${req.params.id}`).emit('newMessage', newMessage);
    
    res.status(201).json(newMessage);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get direct messages between users
app.get('/api/direct-messages/:userId', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    
    const result = await db.query(
      `SELECT dm.*, u1.username as sender_name, u2.username as receiver_name
       FROM direct_messages dm
       JOIN users u1 ON dm.sender_id = u1.id
       JOIN users u2 ON dm.receiver_id = u2.id
       WHERE (dm.sender_id = $1 AND dm.receiver_id = $2) 
          OR (dm.sender_id = $2 AND dm.receiver_id = $1)
       ORDER BY dm.created_at DESC
       LIMIT $3 OFFSET $4`,
      [req.user.id, req.params.userId, limit, offset]
    );
    
    res.json(result.rows.reverse());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch direct messages' });
  }
});

// Send direct message
app.post('/api/direct-messages', authenticateToken, async (req, res) => {
  try {
    const { receiver_id, message, message_type = 'text' } = req.body;
    
    const result = await db.query(
      'INSERT INTO direct_messages (sender_id, receiver_id, message, message_type) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, receiver_id, message, message_type]
    );
    
    const newMessage = result.rows[0];
    
    // Get user info
    const userResult = await db.query(
      'SELECT username, email FROM users WHERE id = $1',
      [req.user.id]
    );
    
    newMessage.sender_name = userResult.rows[0].username;
    newMessage.sender_email = userResult.rows[0].email;
    
    // Emit to both users
    io.to(`user_${req.user.id}`).emit('newDirectMessage', newMessage);
    io.to(`user_${receiver_id}`).emit('newDirectMessage', newMessage);
    
    res.status(201).json(newMessage);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send direct message' });
  }
});

// Create a meeting
app.post('/api/meetings', authenticateToken, async (req, res) => {
  try {
    const { team_id, channel_id, title, description, meeting_type = 'group', scheduled_at, max_participants = 50 } = req.body;
    
    // If it's a team meeting, check if user is team member
    if (team_id) {
      const memberCheck = await db.query(
        'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
        [team_id, req.user.id]
      );
      
      if (memberCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    const result = await db.query(
      'INSERT INTO meetings (team_id, channel_id, title, description, host_id, meeting_type, scheduled_at, max_participants) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [team_id, channel_id, title, description, req.user.id, meeting_type, scheduled_at, max_participants]
    );
    
    const meeting = result.rows[0];
    
    // Add host as participant
    await db.query(
      'INSERT INTO meeting_participants (meeting_id, user_id, is_host) VALUES ($1, $2, $3)',
      [meeting.id, req.user.id, true]
    );
    
    res.status(201).json(meeting);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create meeting' });
  }
});

// Get meetings for a team
app.get('/api/teams/:id/meetings', authenticateToken, async (req, res) => {
  try {
    // Check if user is team member
    const memberCheck = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const result = await db.query(
      `SELECT m.*, u.username as host_name
       FROM meetings m
       JOIN users u ON m.host_id = u.id
       WHERE m.team_id = $1
       ORDER BY m.created_at DESC`,
      [req.params.id]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch meetings' });
  }
});

// Join a meeting
app.post('/api/meetings/:id/join', authenticateToken, async (req, res) => {
  try {
    const meetingId = req.params.id;
    
    // Check if meeting exists and user has access
    const meetingResult = await db.query(
      `SELECT m.*, t.name as team_name
       FROM meetings m
       LEFT JOIN teams t ON m.team_id = t.id
       WHERE m.id = $1`,
      [meetingId]
    );
    
    if (meetingResult.rows.length === 0) {
      return res.status(404).json({ error: 'Meeting not found' });
    }
    
    const meeting = meetingResult.rows[0];
    
    // If it's a team meeting, check if user is team member
    if (meeting.team_id) {
      const memberCheck = await db.query(
        'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
        [meeting.team_id, req.user.id]
      );
      
      if (memberCheck.rows.length === 0) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    // Check if user is already a participant
    const participantCheck = await db.query(
      'SELECT * FROM meeting_participants WHERE meeting_id = $1 AND user_id = $2',
      [meetingId, req.user.id]
    );
    
    if (participantCheck.rows.length === 0) {
      // Add user as participant
      await db.query(
        'INSERT INTO meeting_participants (meeting_id, user_id, joined_at) VALUES ($1, $2, NOW())',
        [meetingId, req.user.id]
      );
    } else {
      // Update join time
      await db.query(
        'UPDATE meeting_participants SET joined_at = NOW(), left_at = NULL WHERE meeting_id = $1 AND user_id = $2',
        [meetingId, req.user.id]
      );
    }
    
    // Update meeting status to active if not already
    if (meeting.status === 'scheduled') {
      await db.query(
        'UPDATE meetings SET status = $1, started_at = NOW() WHERE id = $2',
        ['active', meetingId]
      );
    }
    
    res.json({ success: true, meeting });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to join meeting' });
  }
});

// Add member to team
app.post('/api/teams/:id/members', authenticateToken, async (req, res) => {
  try {
    const { user_id, role = 'member' } = req.body;
    
    // Check if current user is team owner or admin
    const memberCheck = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    
    if (memberCheck.rows.length === 0 || !['owner', 'admin'].includes(memberCheck.rows[0].role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Check if user exists
    const userCheck = await db.query(
      'SELECT id, username, email FROM users WHERE id = $1',
      [user_id]
    );
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user is already a member
    const existingMember = await db.query(
      'SELECT * FROM team_members WHERE team_id = $1 AND user_id = $2',
      [req.params.id, user_id]
    );
    
    if (existingMember.rows.length > 0) {
      return res.status(400).json({ error: 'User is already a team member' });
    }
    
    // Add user to team
    const result = await db.query(
      'INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, user_id, role]
    );
    
    const newMember = result.rows[0];
    newMember.username = userCheck.rows[0].username;
    newMember.email = userCheck.rows[0].email;
    
    // Add user to all public channels
    const channelsResult = await db.query(
      'SELECT id FROM channels WHERE team_id = $1 AND is_private = false',
      [req.params.id]
    );
    
    for (const channel of channelsResult.rows) {
      await db.query(
        'INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [channel.id, user_id]
      );
    }
    
    res.status(201).json(newMember);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add team member' });
  }
});

// Remove member from team
app.delete('/api/teams/:id/members/:userId', authenticateToken, async (req, res) => {
  try {
    const { id: teamId, userId } = req.params;
    
    // Check if current user is team owner or admin
    const memberCheck = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [teamId, req.user.id]
    );
    
    if (memberCheck.rows.length === 0 || !['owner', 'admin'].includes(memberCheck.rows[0].role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Don't allow removing the team owner
    const targetMember = await db.query(
      'SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2',
      [teamId, userId]
    );
    
    if (targetMember.rows.length > 0 && targetMember.rows[0].role === 'owner') {
      return res.status(400).json({ error: 'Cannot remove team owner' });
    }
    
    // Remove user from team
    await db.query(
      'DELETE FROM team_members WHERE team_id = $1 AND user_id = $2',
      [teamId, userId]
    );
    
    // Remove user from all team channels
    await db.query(
      `DELETE FROM channel_members 
       WHERE user_id = $1 AND channel_id IN (
         SELECT id FROM channels WHERE team_id = $2
       )`,
      [userId, teamId]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to remove team member' });
  }
});

// Search users for adding to teams
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q = '', team_id } = req.query;
    
    let query = `
      SELECT u.id, u.username, u.email,
             us.status, us.custom_message, us.last_activity,
             up.is_online, up.last_seen
      FROM users u
      LEFT JOIN user_status us ON u.id = us.user_id
      LEFT JOIN user_presence up ON u.id = up.user_id
      WHERE u.id != $1
    `;
    let params = [req.user.id];
    
    if (q) {
      query += ` AND (u.username ILIKE $2 OR u.email ILIKE $2)`;
      params.push(`%${q}%`);
    }
    
    // If team_id is provided, exclude existing team members
    if (team_id) {
      query += ` AND u.id NOT IN (
        SELECT user_id FROM team_members WHERE team_id = $${params.length + 1}
      )`;
      params.push(team_id);
    }
    
    query += ` ORDER BY u.username LIMIT 20`;
    
    const result = await db.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// ==================== STATUS MANAGEMENT APIs ====================

// Get user status
app.get('/api/users/:id/status', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT us.*, up.is_online, up.last_seen
       FROM user_status us
       LEFT JOIN user_presence up ON us.user_id = up.user_id
       WHERE us.user_id = $1`,
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User status not found' });
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user status' });
  }
});

// Update user status
app.put('/api/users/status', authenticateToken, async (req, res) => {
  try {
    const { status, custom_message } = req.body;
    
    const result = await db.query(
      `INSERT INTO user_status (user_id, status, custom_message, status_updated_at)
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id) 
       DO UPDATE SET 
         status = EXCLUDED.status,
         custom_message = EXCLUDED.custom_message,
         status_updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.id, status, custom_message]
    );
    
    // Log activity
    await db.query(
      'INSERT INTO user_activity (user_id, activity_type, activity_data) VALUES ($1, $2, $3)',
      [req.user.id, 'status_change', JSON.stringify({ status, custom_message })]
    );
    
    // Emit status update to all connected clients
    io.emit('userStatusUpdate', {
      user_id: req.user.id,
      status: result.rows[0].status,
      custom_message: result.rows[0].custom_message,
      updated_at: result.rows[0].status_updated_at
    });
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Update user activity
app.post('/api/users/activity', authenticateToken, async (req, res) => {
  try {
    const { activity_type, activity_data } = req.body;
    
    // Update last activity timestamp
    await db.query(
      `INSERT INTO user_status (user_id, last_activity)
       VALUES ($1, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id) 
       DO UPDATE SET last_activity = CURRENT_TIMESTAMP`,
      [req.user.id]
    );
    
    // Log activity
    await db.query(
      'INSERT INTO user_activity (user_id, activity_type, activity_data) VALUES ($1, $2, $3)',
      [req.user.id, activity_type, JSON.stringify(activity_data || {})]
    );
    
    // Check if user should be marked as away (inactive for 5+ minutes)
    const statusResult = await db.query(
      'SELECT status, last_activity FROM user_status WHERE user_id = $1',
      [req.user.id]
    );
    
    if (statusResult.rows.length > 0) {
      const lastActivity = new Date(statusResult.rows[0].last_activity);
      const now = new Date();
      const minutesSinceActivity = (now - lastActivity) / (1000 * 60);
      
      // Auto-set to away if inactive for 5+ minutes and current status is available
      if (minutesSinceActivity >= 5 && statusResult.rows[0].status === 'available') {
        await db.query(
          'UPDATE user_status SET status = $1, status_updated_at = CURRENT_TIMESTAMP WHERE user_id = $2',
          ['away', req.user.id]
        );
        
        // Emit status update
        io.emit('userStatusUpdate', {
          user_id: req.user.id,
          status: 'away',
          updated_at: new Date().toISOString()
        });
      }
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update activity' });
  }
});

// Get all users with their status
app.get('/api/users/status', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.username, u.email,
              us.status, us.custom_message, us.last_activity, us.status_updated_at,
              up.is_online, up.last_seen
       FROM users u
       LEFT JOIN user_status us ON u.id = us.user_id
       LEFT JOIN user_presence up ON u.id = up.user_id
       ORDER BY u.username`
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users status' });
  }
});

// ==================== SSH KEY MANAGEMENT APIs ====================

// Get user's SSH keys
app.get('/api/ssh-keys', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, title, public_key, fingerprint, created_at, last_used_at FROM ssh_keys WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch SSH keys' });
  }
});

// Add SSH key
app.post('/api/ssh-keys', authenticateToken, async (req, res) => {
  try {
    const { title, public_key } = req.body;
    
    // Validate SSH key format
    if (!public_key.startsWith('ssh-rsa ') && !public_key.startsWith('ssh-ed25519 ') && !public_key.startsWith('ssh-dss ')) {
      return res.status(400).json({ error: 'Invalid SSH key format' });
    }
    
    // Generate fingerprint (simplified - in production, use proper SSH key fingerprinting)
    const fingerprint = require('crypto')
      .createHash('sha256')
      .update(public_key)
      .digest('hex')
      .substring(0, 16);
    
    // Check if key already exists
    const existingKey = await db.query(
      'SELECT id FROM ssh_keys WHERE fingerprint = $1',
      [fingerprint]
    );
    
    if (existingKey.rows.length > 0) {
      return res.status(400).json({ error: 'SSH key already exists' });
    }
    
    const result = await db.query(
      'INSERT INTO ssh_keys (user_id, title, public_key, fingerprint) VALUES ($1, $2, $3, $4) RETURNING id, title, fingerprint, created_at',
      [req.user.id, title, public_key, fingerprint]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add SSH key' });
  }
});

// Delete SSH key
app.delete('/api/ssh-keys/:id', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'DELETE FROM ssh_keys WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'SSH key not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete SSH key' });
  }
});

// Get repository SSH clone URL
app.get('/api/repositories/:id/ssh-url', authenticateToken, async (req, res) => {
  try {
    // Check if user has access to repository
    const accessCheck = await db.query(
      `SELECT r.*, ra.access_type
       FROM repositories r
       LEFT JOIN repository_access ra ON r.id = ra.repository_id AND ra.user_id = $2
       WHERE r.id = $1 AND (r.owner_id = $2 OR ra.user_id = $2 OR r.is_private = false)`,
      [req.params.id, req.user.id]
    );
    
    if (accessCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Repository not found or access denied' });
    }
    
    const repository = accessCheck.rows[0];
    const sshUrl = `ssh://git@localhost:2222/${repository.owner_name}/${repository.name}.git`;
    
    res.json({
      ssh_url: sshUrl,
      repository_name: repository.name,
      owner_name: repository.owner_name
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get SSH URL' });
  }
});

// Socket.IO connection handler
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Handle user authentication and presence
  socket.on('authenticate', async (data) => {
    try {
      const { userId } = data;
      
      // Update user presence
      await db.query(
        `INSERT INTO user_presence (user_id, is_online, last_seen, socket_id)
         VALUES ($1, true, CURRENT_TIMESTAMP, $2)
         ON CONFLICT (user_id) 
         DO UPDATE SET 
           is_online = true,
           last_seen = CURRENT_TIMESTAMP,
           socket_id = $2`,
        [userId, socket.id]
      );
      
      // Join user to their personal room
      socket.join(`user_${userId}`);
      socket.userId = userId;
      
      // Emit presence update to all users
      io.emit('userPresenceUpdate', {
        user_id: userId,
        is_online: true,
        last_seen: new Date().toISOString()
      });
      
      console.log(`User ${userId} authenticated and online`);
    } catch (err) {
      console.error('Authentication error:', err);
    }
  });

  // Join document room for real-time collaboration
  socket.on('joinDocument', (documentId) => {
    socket.join(`document:${documentId}`);
    console.log(`Client ${socket.id} joined document ${documentId}`);
  });

  // Leave document room
  socket.on('leaveDocument', (documentId) => {
    socket.leave(`document:${documentId}`);
    console.log(`Client ${socket.id} left document ${documentId}`);
  });

  // Handle real-time document editing
  socket.on('documentEdit', async (data) => {
    const { documentId, content, userId } = data;
    
    // Broadcast to all clients in the document room except sender
    socket.to(`document:${documentId}`).emit('documentEdit', {
      content,
      userId,
      timestamp: new Date().toISOString()
    });

    // Store document state in Redis for conflict resolution
    await redisUtils.setex(`document:${documentId}:state`, 300, {
      content,
      lastEditedBy: userId,
      lastEditedAt: new Date().toISOString()
    });
  });

  // Handle cursor position updates
  socket.on('cursorUpdate', (data) => {
    const { documentId, position, userId } = data;
    socket.to(`document:${documentId}`).emit('cursorUpdate', {
      position,
      userId,
      timestamp: new Date().toISOString()
    });
  });

  // Video calling handlers
  socket.on('joinVideoRoom', (sessionId) => {
    socket.join(`video:${sessionId}`);
    console.log(`Client ${socket.id} joined video room ${sessionId}`);
  });

  socket.on('leaveVideoRoom', (sessionId) => {
    socket.leave(`video:${sessionId}`);
    console.log(`Client ${socket.id} left video room ${sessionId}`);
  });

  // WebRTC signaling
  socket.on('offer', (data) => {
    const { sessionId, offer, targetUserId } = data;
    socket.to(`video:${sessionId}`).emit('offer', {
      offer,
      fromUserId: data.userId,
      targetUserId
    });
  });

  socket.on('answer', (data) => {
    const { sessionId, answer, targetUserId } = data;
    socket.to(`video:${sessionId}`).emit('answer', {
      answer,
      fromUserId: data.userId,
      targetUserId
    });
  });

  socket.on('iceCandidate', (data) => {
    const { sessionId, candidate, targetUserId } = data;
    socket.to(`video:${sessionId}`).emit('iceCandidate', {
      candidate,
      fromUserId: data.userId,
      targetUserId
    });
  });

  // Repository collaboration handlers
  socket.on('joinRepository', (repositoryId) => {
    socket.join(`repository:${repositoryId}`);
    console.log(`Client ${socket.id} joined repository ${repositoryId}`);
  });

  socket.on('leaveRepository', (repositoryId) => {
    socket.leave(`repository:${repositoryId}`);
    console.log(`Client ${socket.id} left repository ${repositoryId}`);
  });

  socket.on('fileEdit', (data) => {
    const { repositoryId, filePath, content, userId } = data;
    socket.to(`repository:${repositoryId}`).emit('fileEdit', {
      filePath,
      content,
      userId,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('cursorPosition', (data) => {
    const { repositoryId, filePath, position, userId } = data;
    socket.to(`repository:${repositoryId}`).emit('cursorPosition', {
      filePath,
      position,
      userId,
      timestamp: new Date().toISOString()
    });
  });

  // Project management handlers
  socket.on('joinProject', (projectId) => {
    socket.join(`project:${projectId}`);
    console.log(`Client ${socket.id} joined project ${projectId}`);
  });

  socket.on('leaveProject', (projectId) => {
    socket.leave(`project:${projectId}`);
    console.log(`Client ${socket.id} left project ${projectId}`);
  });

  socket.on('issueUpdate', (data) => {
    const { projectId, issueId, updates, userId } = data;
    socket.to(`project:${projectId}`).emit('issueUpdate', {
      issueId,
      updates,
      userId,
      timestamp: new Date().toISOString()
    });
  });

  // ==================== TEAMS Socket.IO Handlers ====================

  // Join team room
  socket.on('joinTeam', (teamId) => {
    socket.join(`team_${teamId}`);
    console.log(`User joined team room: team_${teamId}`);
  });

  socket.on('leaveTeam', (teamId) => {
    socket.leave(`team_${teamId}`);
    console.log(`User left team room: team_${teamId}`);
  });

  // Join channel room
  socket.on('joinChannel', (channelId) => {
    socket.join(`channel_${channelId}`);
    console.log(`User joined channel room: channel_${channelId}`);
  });

  socket.on('leaveChannel', (channelId) => {
    socket.leave(`channel_${channelId}`);
    console.log(`User left channel room: channel_${channelId}`);
  });

  // Join user room for direct messages
  socket.on('joinUser', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User joined user room: user_${userId}`);
  });

  socket.on('leaveUser', (userId) => {
    socket.leave(`user_${userId}`);
    console.log(`User left user room: user_${userId}`);
  });

  // Join meeting room
  socket.on('joinMeeting', (meetingId) => {
    socket.join(`meeting_${meetingId}`);
    console.log(`User joined meeting room: meeting_${meetingId}`);
  });

  socket.on('leaveMeeting', (meetingId) => {
    socket.leave(`meeting_${meetingId}`);
    console.log(`User left meeting room: meeting_${meetingId}`);
  });

  // WebRTC signaling for meetings
  socket.on('meetingSignal', (data) => {
    socket.to(`meeting_${data.meetingId}`).emit('meetingSignal', {
      ...data,
      from: socket.id
    });
  });

  // Typing indicators
  socket.on('typingStart', (data) => {
    socket.to(`channel_${data.channelId}`).emit('userTyping', {
      userId: data.userId,
      username: data.username,
      channelId: data.channelId
    });
  });

  socket.on('typingStop', (data) => {
    socket.to(`channel_${data.channelId}`).emit('userStoppedTyping', {
      userId: data.userId,
      channelId: data.channelId
    });
  });

  socket.on('disconnect', async () => {
    console.log('Client disconnected:', socket.id);
    
    // Update user presence to offline
    if (socket.userId) {
      try {
        await db.query(
          'UPDATE user_presence SET is_online = false, last_seen = CURRENT_TIMESTAMP WHERE user_id = $1',
          [socket.userId]
        );
        
        // Emit presence update to all users
        io.emit('userPresenceUpdate', {
          user_id: socket.userId,
          is_online: false,
          last_seen: new Date().toISOString()
        });
        
        console.log(`User ${socket.userId} went offline`);
      } catch (err) {
        console.error('Error updating presence on disconnect:', err);
      }
    }
  });
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Backend running on port ${port}`);
});
