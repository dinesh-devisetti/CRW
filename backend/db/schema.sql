CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tasks (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  assigned_to INT REFERENCES users(id),
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT DEFAULT '',
  created_by INT REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE document_collaborators (
  id SERIAL PRIMARY KEY,
  document_id INT REFERENCES documents(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  permission VARCHAR(20) DEFAULT 'read', -- 'read', 'write', 'admin'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(document_id, user_id)
);

CREATE TABLE video_sessions (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) UNIQUE NOT NULL,
  created_by INT REFERENCES users(id),
  title VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP
);

CREATE TABLE video_participants (
  id SERIAL PRIMARY KEY,
  session_id INT REFERENCES video_sessions(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  left_at TIMESTAMP,
  UNIQUE(session_id, user_id)
);

-- Repository Management Tables
CREATE TABLE repositories (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  owner_id INT REFERENCES users(id) ON DELETE CASCADE,
  is_private BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(name, owner_id)
);

CREATE TABLE repository_collaborators (
  id SERIAL PRIMARY KEY,
  repository_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  permission VARCHAR(20) DEFAULT 'read', -- 'read', 'write', 'admin'
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(repository_id, user_id)
);

CREATE TABLE branches (
  id SERIAL PRIMARY KEY,
  repository_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  is_default BOOLEAN DEFAULT false,
  created_by INT REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(repository_id, name)
);

CREATE TABLE commits (
  id SERIAL PRIMARY KEY,
  repository_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  branch_id INT REFERENCES branches(id) ON DELETE CASCADE,
  commit_hash VARCHAR(40) UNIQUE NOT NULL,
  message TEXT NOT NULL,
  author_id INT REFERENCES users(id),
  parent_commit_id INT REFERENCES commits(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE files (
  id SERIAL PRIMARY KEY,
  repository_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  commit_id INT REFERENCES commits(id) ON DELETE CASCADE,
  file_path VARCHAR(500) NOT NULL,
  content TEXT,
  file_type VARCHAR(50),
  size_bytes INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pull_requests (
  id SERIAL PRIMARY KEY,
  repository_id INT REFERENCES repositories(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  source_branch_id INT REFERENCES branches(id),
  target_branch_id INT REFERENCES branches(id),
  author_id INT REFERENCES users(id),
  status VARCHAR(20) DEFAULT 'open', -- 'open', 'closed', 'merged'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  merged_at TIMESTAMP,
  merged_by INT REFERENCES users(id)
);

CREATE TABLE pull_request_reviews (
  id SERIAL PRIMARY KEY,
  pull_request_id INT REFERENCES pull_requests(id) ON DELETE CASCADE,
  reviewer_id INT REFERENCES users(id),
  status VARCHAR(20) NOT NULL, -- 'approved', 'changes_requested', 'commented'
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pull_request_comments (
  id SERIAL PRIMARY KEY,
  pull_request_id INT REFERENCES pull_requests(id) ON DELETE CASCADE,
  file_path VARCHAR(500),
  line_number INT,
  comment TEXT NOT NULL,
  author_id INT REFERENCES users(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Jira-like Project Management Tables
CREATE TABLE projects (
  id SERIAL PRIMARY KEY,
  key VARCHAR(10) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  project_type VARCHAR(50) DEFAULT 'software', -- 'software', 'business', 'service_desk'
  lead_id INT REFERENCES users(id),
  avatar_url VARCHAR(500),
  is_private BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE project_members (
  id SERIAL PRIMARY KEY,
  project_id INT REFERENCES projects(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(50) DEFAULT 'member', -- 'admin', 'member', 'viewer'
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, user_id)
);

CREATE TABLE issue_types (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  icon VARCHAR(50),
  color VARCHAR(7),
  is_subtask BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE priorities (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) NOT NULL,
  description TEXT,
  icon VARCHAR(50),
  color VARCHAR(7),
  level INT DEFAULT 3, -- 1=highest, 5=lowest
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE statuses (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  category VARCHAR(50) DEFAULT 'todo', -- 'todo', 'in_progress', 'done'
  color VARCHAR(7),
  is_final BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workflows (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  project_id INT REFERENCES projects(id) ON DELETE CASCADE,
  is_default BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workflow_transitions (
  id SERIAL PRIMARY KEY,
  workflow_id INT REFERENCES workflows(id) ON DELETE CASCADE,
  from_status_id INT REFERENCES statuses(id),
  to_status_id INT REFERENCES statuses(id),
  name VARCHAR(255),
  description TEXT,
  is_automatic BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE issues (
  id SERIAL PRIMARY KEY,
  key VARCHAR(50) UNIQUE NOT NULL, -- e.g., PROJ-123
  project_id INT REFERENCES projects(id) ON DELETE CASCADE,
  issue_type_id INT REFERENCES issue_types(id),
  priority_id INT REFERENCES priorities(id),
  status_id INT REFERENCES statuses(id),
  summary VARCHAR(500) NOT NULL,
  description TEXT,
  reporter_id INT REFERENCES users(id),
  assignee_id INT REFERENCES users(id),
  parent_issue_id INT REFERENCES issues(id), -- for subtasks
  story_points INT,
  time_estimate INT, -- in minutes
  time_spent INT DEFAULT 0, -- in minutes
  due_date TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  resolved_at TIMESTAMP
);

CREATE TABLE issue_comments (
  id SERIAL PRIMARY KEY,
  issue_id INT REFERENCES issues(id) ON DELETE CASCADE,
  author_id INT REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE issue_attachments (
  id SERIAL PRIMARY KEY,
  issue_id INT REFERENCES issues(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_size INT,
  mime_type VARCHAR(100),
  uploaded_by INT REFERENCES users(id),
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE issue_watchers (
  id SERIAL PRIMARY KEY,
  issue_id INT REFERENCES issues(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(issue_id, user_id)
);

CREATE TABLE sprints (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  project_id INT REFERENCES projects(id) ON DELETE CASCADE,
  goal TEXT,
  start_date TIMESTAMP,
  end_date TIMESTAMP,
  state VARCHAR(50) DEFAULT 'future', -- 'future', 'active', 'closed'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sprint_issues (
  id SERIAL PRIMARY KEY,
  sprint_id INT REFERENCES sprints(id) ON DELETE CASCADE,
  issue_id INT REFERENCES issues(id) ON DELETE CASCADE,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(sprint_id, issue_id)
);

CREATE TABLE issue_history (
  id SERIAL PRIMARY KEY,
  issue_id INT REFERENCES issues(id) ON DELETE CASCADE,
  field_name VARCHAR(100) NOT NULL,
  old_value TEXT,
  new_value TEXT,
  changed_by INT REFERENCES users(id),
  changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Teams (Microsoft Teams-like groups)
CREATE TABLE teams (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  owner_id INT REFERENCES users(id) ON DELETE CASCADE,
  is_private BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Team members
CREATE TABLE team_members (
  id SERIAL PRIMARY KEY,
  team_id INT REFERENCES teams(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(team_id, user_id)
);

-- Channels within teams
CREATE TABLE channels (
  id SERIAL PRIMARY KEY,
  team_id INT REFERENCES teams(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  is_private BOOLEAN DEFAULT false,
  created_by INT REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(team_id, name)
);

-- Channel members
CREATE TABLE channel_members (
  id SERIAL PRIMARY KEY,
  channel_id INT REFERENCES channels(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(channel_id, user_id)
);

-- Chat messages
CREATE TABLE chat_messages (
  id SERIAL PRIMARY KEY,
  channel_id INT REFERENCES channels(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  message_type VARCHAR(20) DEFAULT 'text' CHECK (message_type IN ('text', 'file', 'image', 'meeting_invite')),
  file_url VARCHAR(500),
  reply_to INT REFERENCES chat_messages(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Direct messages (individual chats)
CREATE TABLE direct_messages (
  id SERIAL PRIMARY KEY,
  sender_id INT REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  message_type VARCHAR(20) DEFAULT 'text' CHECK (message_type IN ('text', 'file', 'image', 'call_invite')),
  file_url VARCHAR(500),
  is_read BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Meetings (group video calls)
CREATE TABLE meetings (
  id SERIAL PRIMARY KEY,
  team_id INT REFERENCES teams(id) ON DELETE CASCADE,
  channel_id INT REFERENCES channels(id) ON DELETE SET NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  host_id INT REFERENCES users(id) ON DELETE CASCADE,
  meeting_type VARCHAR(20) DEFAULT 'group' CHECK (meeting_type IN ('group', 'direct')),
  status VARCHAR(20) DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'active', 'ended')),
  scheduled_at TIMESTAMP,
  started_at TIMESTAMP,
  ended_at TIMESTAMP,
  max_participants INT DEFAULT 50,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Meeting participants
CREATE TABLE meeting_participants (
  id SERIAL PRIMARY KEY,
  meeting_id INT REFERENCES meetings(id) ON DELETE CASCADE,
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP,
  left_at TIMESTAMP,
  is_host BOOLEAN DEFAULT false,
  UNIQUE(meeting_id, user_id)
);

-- Meeting recordings (optional)
CREATE TABLE meeting_recordings (
  id SERIAL PRIMARY KEY,
  meeting_id INT REFERENCES meetings(id) ON DELETE CASCADE,
  recording_url VARCHAR(500) NOT NULL,
  duration_seconds INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default data
INSERT INTO issue_types (name, description, icon, color, is_subtask) VALUES
('Story', 'A user story', '📖', '#0052CC', false),
('Task', 'A task that needs to be done', '✅', '#36B37E', false),
('Bug', 'A problem that needs to be fixed', '🐛', '#DE350B', false),
('Epic', 'A large body of work', '🎯', '#7A869A', false),
('Sub-task', 'A sub-task of a parent issue', '📋', '#5E6C84', true);

INSERT INTO priorities (name, description, icon, color, level) VALUES
('Highest', 'This issue is blocking other work', '🔴', '#CD1316', 1),
('High', 'This issue is important', '🟠', '#E97F33', 2),
('Medium', 'This issue has normal priority', '🟡', '#F7D460', 3),
('Low', 'This issue is not urgent', '🟢', '#36B37E', 4),
('Lowest', 'This issue can be done when time permits', '🔵', '#0052CC', 5);

INSERT INTO statuses (name, description, category, color, is_final) VALUES
('To Do', 'The issue is open and ready for the assignee to start work on it', 'todo', '#42526E', false),
('In Progress', 'This issue is being actively worked on at the moment by the assignee', 'in_progress', '#0052CC', false),
('Done', 'Work has finished on the issue', 'done', '#00875A', true),
('Closed', 'The issue is closed', 'done', '#42526E', true);
