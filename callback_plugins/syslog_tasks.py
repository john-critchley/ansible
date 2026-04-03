"""
Ansible callback plugin: syslog_tasks
Logs each task result to syslog (facility USER) with brief status codes.

Status codes:
  OK    - task ran, no change
  CHNG  - task ran, host changed
  SKIP  - task skipped (when: condition false)
  FAIL  - task failed (fatal)
  IGN   - task failed but ignore_errors: true
  UNRCH - host unreachable
  RESC  - task rescued by a rescue block
  PLAY  - start of a play (informational)
  DONE  - final per-host summary

Messages are tagged "ansible" so rsyslog can route them to /var/log/ansible.log.
"""

from ansible.plugins.callback import CallbackBase
import syslog

DOCUMENTATION = r'''
    name: syslog_tasks
    type: notification
    short_description: Log task results to syslog USER facility
'''

_PRIORITY = {
    'OK':    syslog.LOG_INFO,
    'CHNG':  syslog.LOG_INFO,
    'SKIP':  syslog.LOG_DEBUG,
    'FAIL':  syslog.LOG_ERR,
    'IGN':   syslog.LOG_WARNING,
    'UNRCH': syslog.LOG_CRIT,
    'RESC':  syslog.LOG_WARNING,
    'PLAY':  syslog.LOG_INFO,
    'DONE':  syslog.LOG_INFO,
}


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'syslog_tasks'
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self):
        super().__init__()
        syslog.openlog(ident='ansible', logoption=syslog.LOG_PID,
                       facility=syslog.LOG_USER)

    def _log(self, status, host, task_name):
        name = task_name.strip()
        if len(name) > 60:
            name = name[:57] + '...'
        syslog.syslog(_PRIORITY[status],
                      f'{status:<5} host={host} task={name!r}')

    def v2_runner_on_ok(self, result):
        host = result._host.get_name()
        name = result._task.get_name()
        self._log('CHNG' if result.is_changed() else 'OK', host, name)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        host = result._host.get_name()
        name = result._task.get_name()
        self._log('IGN' if ignore_errors else 'FAIL', host, name)

    def v2_runner_on_skipped(self, result):
        host = result._host.get_name()
        name = result._task.get_name()
        self._log('SKIP', host, name)

    def v2_runner_on_unreachable(self, result):
        host = result._host.get_name()
        name = result._task.get_name()
        self._log('UNRCH', host, name)

    def v2_runner_on_rescued(self, result):
        host = result._host.get_name()
        name = result._task.get_name()
        self._log('RESC', host, name)

    def v2_playbook_on_play_start(self, play):
        syslog.syslog(syslog.LOG_INFO,
                      f'PLAY  play={play.get_name()!r}')

    def v2_playbook_on_stats(self, stats):
        for host in sorted(stats.processed.keys()):
            s = stats.summarize(host)
            syslog.syslog(syslog.LOG_INFO,
                          f'DONE  host={host} '
                          f'ok={s["ok"]} chng={s["changed"]} '
                          f'fail={s["failures"]} skip={s["skipped"]} '
                          f'unrch={s["unreachable"]}')
