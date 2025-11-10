
// static struct file *task_get_exe_file(struct task_struct *task) {
//     struct file *exe_file = NULL;
//     struct mm_struct *mm;
  
//     if (!task)
//       return NULL;
  
//     mm = get_task_mm(task);
//     if (!mm)
//       return NULL;
  
//     mmap_read_lock(mm);
//     if (mm->exe_file)
//       exe_file = get_file(mm->exe_file);
//     mmap_read_unlock(mm);
  
//     mmput(mm);
  
//     return exe_file;
//   }
  
//   static void task_exe_path(struct task_struct *task, char *buf, size_t buflen) {
//     struct file *exe_file;
//     char *path;
  
//     if (!buf || buflen == 0)
//       return;
  
//     buf[0] = '\0';
  
//     exe_file = task_get_exe_file(task);
//     if (!exe_file)
//       return;
  
//     path = d_path(&exe_file->f_path, buf, buflen);
//     if (IS_ERR(path)) {
//       buf[0] = '\0';
//     } else if (path != buf) {
//       size_t len = strnlen(path, buflen - 1);
//       memmove(buf, path, len);
//       buf[len] = '\0';
//     }
  
//     fput(exe_file);
//   }
  
//   static struct task_struct *task_get_by_pid(pid_t pid) {
//     struct pid *pid_struct = find_get_pid(pid);
//     if (!pid_struct)
//       return NULL;
  
//     struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
  
//     put_pid(pid_struct);
//     return task;
//   }
  
//   struct fork_event_work {
//     struct work_struct work;
//     struct fork_event_data data;
//   };
  
//   static void fork_event_workfn(struct work_struct *work) {
//     struct fork_event_work *event_work =
//         container_of(work, struct fork_event_work, work);
//     struct fork_event_data *event = &event_work->data;
//     struct task_struct *parent_task = NULL;
//     struct task_struct *child_task = NULL;
//     int ret;
  
//     parent_task = task_get_by_pid(event->parent_pid);
//     if (parent_task) {
//       task_exe_path(parent_task, event->parent_path, sizeof(event->parent_path));
//       put_task_struct(parent_task);
//     } else {
//       event->parent_path[0] = '\0';
//     }
  
//     child_task = task_get_by_pid(event->child_pid);
//     if (child_task) {
//       task_exe_path(child_task, event->child_path, sizeof(event->child_path));
//       put_task_struct(child_task);
//     } else {
//       event->child_path[0] = '\0';
//     }
  
//     ret = genl_core_send_fork_event(event);
//     if (ret && ret != -ESRCH)
//       pr_debug("%s: send netlink message failed: %d\n", __func__, ret);
  
//     kfree(event_work);
//   }
  