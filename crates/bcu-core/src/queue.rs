use crate::models::{ApplicationEntry, UninstallerKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct UninstallTask {
    pub app: ApplicationEntry,
    pub status: TaskStatus,
}

pub struct UninstallQueue {
    tasks: Vec<UninstallTask>,
}

impl Default for UninstallQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl UninstallQueue {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    pub fn add(&mut self, app: ApplicationEntry) {
        self.tasks.push(UninstallTask {
            app,
            status: TaskStatus::Pending,
        });
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn is_msi_running(&self) -> bool {
        self.tasks.iter().any(|t| {
            t.status == TaskStatus::Running && t.app.uninstaller_kind == UninstallerKind::Msi
        })
    }

    /// Finds the next runnable pending task.
    /// If an MSI task is currently running, pending MSI tasks are deferred to prevent
    /// Windows Installer collision (Error 1618: Another installation is in progress).
    pub fn next_runnable_task(&self) -> Option<&UninstallTask> {
        let msi_busy = self.is_msi_running();
        self.tasks.iter().find(|t| {
            if t.status != TaskStatus::Pending {
                return false;
            }
            if msi_busy && t.app.uninstaller_kind == UninstallerKind::Msi {
                return false;
            }
            true
        })
    }

    pub fn set_status(&mut self, app_id: &str, status: TaskStatus) {
        if let Some(task) = self.tasks.iter_mut().find(|t| {
            t.app.id == app_id && !matches!(t.status, TaskStatus::Completed | TaskStatus::Failed)
        }) {
            task.status = status;
        }
    }

    pub fn all_tasks(&self) -> &[UninstallTask] {
        &self.tasks
    }
}
