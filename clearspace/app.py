"""Native desktop UI, confirmation flow, and background task orchestration."""
import queue
import math
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
import webbrowser

from .client import CoreClient
from .action_groups import action_group
from . import workflow

BG = '#f3f5f2'
WHITE = '#ffffff'
INK = '#172d2b'
MUTED = '#73837f'
LINE = '#dfe8e3'
GREEN = '#276f60'
GREEN_DARK = '#1d5d50'
MINT = '#e4f1ea'
NAV = '#17332e'
NAV2 = '#244a41'
AMBER = '#9a632e'
FONT = 'Microsoft YaHei UI'


class AnimatedMark(tk.Canvas):
    """Subtle local animation; it does not perform any background work."""
    def __init__(self, parent, motion):
        super().__init__(parent, width=42, height=42, bg=NAV, highlightthickness=0)
        self.motion = motion
        self.angle = 0
        self._timer = None
        self.create_oval(4, 4, 38, 38, outline='#46786a', width=2)
        self.create_arc(9, 9, 33, 33, start=35, extent=275, outline='#bde2cb', width=3, style='arc')
        self.dot = self.create_oval(0, 0, 6, 6, fill='#e3ba91', outline='')
        self._tick()

    def _tick(self):
        if self._timer:
            self.after_cancel(self._timer)
        angle = math.radians(self.angle)
        x, y = 21 + 17 * math.cos(angle), 21 - 17 * math.sin(angle)
        self.coords(self.dot, x - 3, y - 3, x + 3, y + 3)
        if self.motion.get():
            self.angle = (self.angle + 3) % 360
        self._timer = self.after(70, self._tick)

    def destroy(self):
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None
        super().destroy()

def label(parent, text='', size=10, color=INK, bold=False, bg=None, **kwargs):
    return tk.Label(parent, text=text, font=(FONT, size, 'bold' if bold else 'normal'),
                    fg=color, bg=bg or parent.cget('bg'), anchor='w', **kwargs)


def button(parent, text, command, primary=False, **kw):
    kw.setdefault('padx', 18)
    kw.setdefault('pady', 10)
    return tk.Button(parent, text=text, command=command, bd=0, relief='flat',
                     font=(FONT, 10, 'bold'), cursor='hand2',
                     bg=GREEN if primary else WHITE, fg=WHITE if primary else INK,
                     activebackground=GREEN_DARK if primary else MINT,
                     activeforeground=WHITE if primary else GREEN, **kw)


def size_text(size):
    n = float(size or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


class ScrollFrame(tk.Frame):
    def __init__(self, parent, background=BG):
        super().__init__(parent, bg=background)
        self.canvas = tk.Canvas(self, bd=0, highlightthickness=0, bg=background)
        bar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=bar.set)
        bar.pack(side='right', fill='y')
        self.canvas.pack(side='left', fill='both', expand=True)
        self.body = tk.Frame(self.canvas, bg=background)
        self.window = self.canvas.create_window((0, 0), window=self.body, anchor='nw')
        self.body.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(self.window, width=e.width))
        self.canvas.bind_all('<MouseWheel>', self._wheel, add='+')

    def _wheel(self, event):
        if self.winfo_ismapped() and self.winfo_containing(event.x_root, event.y_root):
            widget = self.winfo_containing(event.x_root, event.y_root)
            while widget:
                if widget == self:
                    self.canvas.yview_scroll(-int(event.delta / 120), 'units')
                    break
                widget = widget.master


class ConfirmDialog(tk.Toplevel):
    def __init__(self, parent, data):
        super().__init__(parent)
        self.result = False
        self.title(data['title'])
        self.configure(bg=WHITE)
        self.transient(parent)
        self.resizable(False, False)
        self.geometry('650x570')
        self.protocol('WM_DELETE_WINDOW', self.destroy)
        shell = tk.Frame(self, bg=WHITE, padx=28, pady=24)
        shell.pack(fill='both', expand=True)
        label(shell, 'PLEASE REVIEW', 9, GREEN, True).pack(anchor='w')
        label(shell, data['title'], 20, INK, True).pack(anchor='w', pady=(4, 10))
        label(shell, data['detail'], 10, MUTED, wraplength=580, justify='left').pack(anchor='w', pady=(0, 15))
        box = tk.Frame(shell, bg=BG, padx=12, pady=10)
        box.pack(fill='both', expand=True)
        text = tk.Text(box, bg=BG, fg=INK, bd=0, relief='flat', font=(FONT, 10),
                       wrap='word', height=9, highlightthickness=0)
        scroll = ttk.Scrollbar(box, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(fill='both', expand=True)
        text.insert('1.0', '\n'.join(data.get('items', [])))
        text.configure(state='disabled')
        self.checked = tk.BooleanVar(value=False)
        check = tk.Checkbutton(shell, text='我已阅读上述范围并了解操作影响', variable=self.checked,
                               command=self._toggle, bg=WHITE, fg=INK, activebackground=WHITE,
                               selectcolor=WHITE, font=(FONT, 10), anchor='w')
        check.pack(fill='x', pady=(16, 10))
        actions = tk.Frame(shell, bg=WHITE)
        actions.pack(fill='x')
        self.accept = button(actions, '确认执行', self._accept, primary=True, state='disabled')
        self.accept.pack(side='right')
        button(actions, '取消', self.destroy).pack(side='right', padx=8)
        self.grab_set()
        self.focus_set()
        self.wait_window()

    def _toggle(self):
        self.accept.configure(state='normal' if self.checked.get() else 'disabled')

    def _accept(self):
        self.result = True
        self.destroy()


class ClearspaceApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('澄界 · Claude 本地指纹与数据清理')
        self.geometry('1280x820')
        self.minsize(1020, 680)
        self.configure(bg=BG)
        icon = Path(__file__).resolve().parent.parent / 'legacy' / 'assets' / 'icon.ico'
        try:
            self.iconbitmap(str(icon))
        except tk.TclError:
            pass
        self.core = CoreClient()
        self.messages = queue.Queue()
        self.busy = False
        self.status_text = '就绪'
        self.animation_step = 0
        self.motion = tk.BooleanVar(value=True)
        self.view = 'clean'
        self.targets = []
        self.actions = []
        self.selections = {}
        self.action_selections = {}
        self.recovery = None
        self.scroll = None
        self.repair_proxy = tk.BooleanVar(value=True)
        self.result_text = ''
        self._build_shell()
        self.render()
        self._poll_job = self.after(80, self._poll)
        self._animation_job = self.after(160, self._animate_status)
        self.protocol('WM_DELETE_WINDOW', self._close)
        self._work('正在载入设置…', 'actions', self._actions_loaded)

    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg=NAV, width=224, padx=21, pady=25)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)
        mark = tk.Frame(self.sidebar, bg=NAV)
        mark.pack(fill='x', pady=(0, 35))
        AnimatedMark(mark, self.motion).pack(side='left', padx=(0, 10))
        word = tk.Frame(mark, bg=NAV)
        word.pack(side='left')
        label(word, '澄界', 16, WHITE, True, bg=NAV).pack(anchor='w')
        label(word, 'CLAUDE CLEANER', 8, '#9ebdb0', True, bg=NAV).pack(anchor='w')
        label(self.sidebar, '工作空间', 9, '#8daca0', True, bg=NAV).pack(anchor='w', pady=(0, 10))
        self.nav_buttons = {}
        for key, name in [('clean', '◫   数据清理'), ('browser', '◇   浏览器设置'),
                          ('system', '◈   系统设置'), ('recovery', '↗   网络恢复')]:
            nav = tk.Button(self.sidebar, text=name, command=lambda k=key: self._navigate(k),
                            anchor='w', bd=0, relief='flat', cursor='hand2', font=(FONT, 10, 'bold'),
                            padx=12, pady=12, activebackground=NAV2, activeforeground=WHITE)
            nav.pack(fill='x', pady=3)
            self.nav_buttons[key] = nav
            nav.bind('<Enter>', lambda event, k=key: self._nav_hover(k, True))
            nav.bind('<Leave>', lambda event, k=key: self._nav_hover(k, False))
        foot = tk.Frame(self.sidebar, bg=NAV)
        foot.pack(side='bottom', fill='x')
        tk.Frame(foot, bg='#345149', height=1).pack(fill='x', pady=(0, 18))
        tk.Checkbutton(foot, text='动态效果', variable=self.motion, command=self._motion_changed,
                       bg=NAV, fg='#c2ddcf', activebackground=NAV, activeforeground=WHITE,
                       selectcolor=NAV2, font=(FONT, 9), anchor='w').pack(anchor='w', pady=(0, 10))
        label(foot, '●   本地隐私工作台', 10, '#c2ddcf', True, bg=NAV).pack(anchor='w')
        label(foot, '非 Anthropic 官方 · 预览版', 8, '#8daca0', bg=NAV).pack(anchor='w', pady=(6, 0))
        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side='left', fill='both', expand=True)
        top = tk.Frame(self.main, bg=BG, padx=32, pady=14)
        top.pack(fill='x')
        label(top, 'CLEARSPACE  /  CLAUDE 本地清理', 9, MUTED, True, bg=BG).pack(side='left')
        self.status = label(top, '●  就绪', 9, GREEN, bg=BG)
        self.status.pack(side='right')
        style = ttk.Style(self)
        style.configure('Clearspace.Horizontal.TProgressbar', troughcolor=BG, background=GREEN, borderwidth=0, thickness=3)
        self.progress = ttk.Progressbar(self.main, mode='indeterminate', style='Clearspace.Horizontal.TProgressbar')
        tk.Frame(self.main, bg=LINE, height=1).pack(fill='x', padx=32)
        self.page = tk.Frame(self.main, bg=BG)
        self.page.pack(fill='both', expand=True, padx=32, pady=(20, 12))

    def _nav_hover(self, key, entered):
        if key != self.view:
            self.nav_buttons[key].configure(bg=NAV2 if entered else NAV)

    def _motion_changed(self):
        if self.busy and self.motion.get():
            self.progress.pack(fill='x', padx=32, before=self.page)
            self.progress.start(15)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def _animate_status(self):
        if self.busy:
            self.animation_step = (self.animation_step + 1) % 4
            dots = '·' * (self.animation_step + 1) if self.motion.get() else ''
            self.status.configure(text=f'●  {self.status_text}{dots}', fg=AMBER)
        self._animation_job = self.after(160, self._animate_status)

    def _navigate(self, view):
        self.view = view
        self.result_text = ''
        self.render()

    def _work(self, status, command, callback, **payload):
        self._work_callable(status, lambda progress: self.core.call(command, **payload), callback)

    def _work_callable(self, status, task, callback):
        if self.busy:
            messagebox.showinfo('请稍候', '另一项操作正在进行。', parent=self)
            return
        self.busy = True
        self.status_text = status.rstrip('…')
        self.status.configure(text='●  ' + self.status_text, fg=AMBER)
        self._motion_changed()
        def run():
            try:
                self.messages.put((callback, task(lambda message: self.messages.put((None, message, None))), None))
            except Exception as error:
                self.messages.put((callback, None, error))
        threading.Thread(target=run, daemon=True).start()

    def _poll(self):
        try:
            while True:
                callback, result, error = self.messages.get_nowait()
                if callback is None:
                    self.status_text = result.rstrip('…')
                    self.status.configure(text='●  ' + self.status_text, fg=AMBER)
                    continue
                self.busy = False
                self._motion_changed()
                self.status.configure(text='●  就绪', fg=GREEN)
                if error:
                    messagebox.showerror('操作未完成', str(error), parent=self)
                else:
                    callback(result)
        except queue.Empty:
            pass
        self._poll_job = self.after(80, self._poll)

    def _actions_loaded(self, actions):
        self.actions = actions
        if self.view in ('browser', 'system'):
            self.render()

    def _close(self):
        if self.busy:
            messagebox.showinfo('操作进行中', '请等待当前操作结束后再退出。', parent=self)
            return
        self.core.close()
        self.destroy()

    def destroy(self):
        self.progress.stop()
        for job in (getattr(self, '_poll_job', None), getattr(self, '_animation_job', None)):
            if job:
                self.after_cancel(job)
        super().destroy()

    def render(self):
        self.unbind_all('<MouseWheel>')
        self.scroll = None
        for child in self.page.winfo_children():
            child.destroy()
        for key, nav in self.nav_buttons.items():
            nav.configure(bg=NAV2 if key == self.view else NAV, fg=WHITE if key == self.view else '#b1c9bd')
        {'clean': self._render_clean, 'browser': self._render_privacy,
         'system': self._render_privacy, 'recovery': self._render_recovery}[self.view]()

    def _header(self, eyebrow, title, subtitle, action=None, extra_actions=()):
        head = tk.Frame(self.page, bg=BG)
        head.pack(fill='x', pady=(0, 20))
        left = tk.Frame(head, bg=BG)
        left.pack(side='left', fill='x', expand=True)
        label(left, eyebrow, 9, GREEN, True).pack(anchor='w')
        label(left, title, 23, INK, True).pack(anchor='w', pady=(3, 4))
        label(left, subtitle, 10, MUTED, wraplength=670, justify='left').pack(anchor='w')
        if action:
            button(head, action[0], action[1], primary=True).pack(side='right', padx=(12, 0))
        for caption, command in extra_actions:
            button(head, caption, command, padx=10).pack(side='right', padx=(5, 0))

    def _strip(self, parent, heading, detail):
        frame = tk.Frame(parent, bg='#edf4ee', padx=18, pady=12)
        frame.pack(fill='x', pady=(0, 16))
        label(frame, heading, 10, GREEN_DARK, True).pack(anchor='w')
        detail_label = label(frame, detail, 9, '#617a6e', wraplength=600, justify='left')
        detail_label.pack(anchor='w', fill='x', pady=(4, 0))
        frame.bind('<Configure>', lambda event: detail_label.configure(wraplength=max(100, event.width - 45)))

    def _stats(self, entries):
        row = tk.Frame(self.page, bg=BG)
        row.pack(fill='x', pady=(0, 16))
        for index, (caption, value, note) in enumerate(entries):
            row.columnconfigure(index, weight=1, uniform='stats')
            card = tk.Frame(row, bg=WHITE, padx=18, pady=14, highlightbackground=LINE, highlightthickness=1)
            card.grid(row=0, column=index, sticky='nsew', padx=(0 if index == 0 else 6, 0 if index == len(entries)-1 else 6))
            label(card, caption, 9, MUTED).pack(anchor='w')
            label(card, value, 18, INK, True).pack(anchor='w', pady=(5, 0))
            label(card, note, 9, GREEN).pack(anchor='w', pady=(4, 0))

    def _section(self, title, sub='', action=None):
        row = tk.Frame(self.page, bg=BG)
        row.pack(fill='x', pady=(0, 8))
        label(row, title, 13, INK, True).pack(side='left')
        if sub:
            label(row, sub, 9, MUTED).pack(side='left', padx=10)
        if action:
            button(row, action[0], action[1], primary=True, pady=6).pack(side='right')

    def _result(self):
        if self.result_text:
            panel = tk.Frame(self.page, bg='#e6f2eb', padx=14, pady=10)
            panel.pack(fill='x', pady=(0, 12))
            button(panel, '查看详情', self._show_result_details, padx=8, pady=3).pack(side='right', padx=(10, 0))
            lines = self.result_text.splitlines()
            preview = '\n'.join(line[:140] + ('…' if len(line) > 140 else '') for line in lines[:2])
            if len(lines) > 2:
                preview += '\n…'
            label(panel, preview, 9, GREEN_DARK, wraplength=650, justify='left').pack(anchor='w', fill='x')

    def _show_result_details(self):
        dialog = tk.Toplevel(self)
        dialog.title('操作结果')
        dialog.geometry('720x500')
        dialog.configure(bg=WHITE)
        dialog.transient(self)
        body = tk.Frame(dialog, bg=WHITE, padx=24, pady=20)
        body.pack(fill='both', expand=True)
        label(body, '操作结果', 17, INK, True).pack(anchor='w', pady=(0, 12))
        box = tk.Frame(body, bg=BG)
        box.pack(fill='both', expand=True)
        text = tk.Text(box, bg=BG, fg=INK, bd=0, relief='flat', font=(FONT, 10), wrap='word', padx=12, pady=10)
        scroll = ttk.Scrollbar(box, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(fill='both', expand=True)
        text.insert('1.0', self.result_text)
        text.configure(state='disabled')
        button(body, '关闭', dialog.destroy, primary=True).pack(anchor='e', pady=(12, 0))

    def _render_clean(self):
        self._header('CLAUDE LOCAL CLEANUP', 'Claude 本地数据与指纹', '扫描 Claude 桌面端、Claude Code 与相关浏览器数据，确认后再清理。',
                     ('一键启动', self._prepare_one_click),
                     [('一键恢复', self._prepare_one_click_restore), ('↻ 扫描', self._scan)])
        available = [t for t in self.targets if t.get('exists') and not t.get('blockedReason')]
        chosen = [t for t in available if self.selections.get(t['id'], False)]
        self._stats([('可用项目', str(len(available)) if self.targets else '—', '等待选择' if available else '扫描后显示'),
                     ('已选项目', str(len(chosen)), '逐项确认'),
                     ('预计大小', size_text(sum(t.get('bytes', 0) for t in chosen)), '部分目录可能为估算')])
        self._strip(self.page, '先核对范围，再执行清理', '清理不可恢复；浏览器清理项可能删除全部网站的 Cookie、缓存和站点数据。本地清理不能清除服务端记录，也不能保证消除所有指纹。')
        self._result()
        self._section('扫描结果', '  ·  点击卡片左侧勾选项目', ('清理所选', self._prepare_clean))
        scroll = ScrollFrame(self.page)
        scroll.pack(fill='both', expand=True)
        self.scroll = scroll
        if not self.targets:
            self._empty(scroll.body, '尚未扫描 Claude 相关数据', '点击右上角“扫描”，查看可处理的本地项目与具体路径。')
            return
        for target in self.targets:
            self._target_card(scroll.body, target)

    def _empty(self, parent, title, detail):
        frame = tk.Frame(parent, bg=WHITE, padx=25, pady=35, highlightbackground=LINE, highlightthickness=1)
        frame.pack(fill='x')
        label(frame, '✳', 21, GREEN).pack()
        label(frame, title, 13, INK, True).pack(pady=(10, 4))
        label(frame, detail, 10, MUTED, wraplength=650, justify='center').pack()

    def _target_card(self, parent, target):
        exists = target.get('exists') and not target.get('blockedReason')
        card = tk.Frame(parent, bg=WHITE, padx=14, pady=12, highlightbackground=LINE, highlightthickness=1)
        card.pack(fill='x', pady=(0, 8))
        var = tk.BooleanVar(value=self.selections.get(target['id'], False))
        check = tk.Checkbutton(card, variable=var, bg=WHITE, activebackground=WHITE, selectcolor=WHITE,
                               state='normal' if exists else 'disabled', command=lambda: self._toggle_target(target, var.get()))
        check.pack(side='left', anchor='n', padx=(0, 8))
        content = tk.Frame(card, bg=WHITE)
        content.pack(side='left', fill='x', expand=True)
        label(content, target['title'], 10, INK if exists else MUTED, True).pack(anchor='w')
        label(content, target.get('description', ''), 9, MUTED, wraplength=670, justify='left').pack(anchor='w', pady=(4, 0))
        paths = [r.get('displayPath', '') for r in target.get('resources', []) if r.get('exists')]
        if paths:
            label(content, '  ·  '.join(paths), 8, '#8a9a93', wraplength=670, justify='left').pack(anchor='w', pady=(4, 0))
        if target.get('blockedReason'):
            label(content, target['blockedReason'], 9, AMBER, wraplength=670, justify='left').pack(anchor='w', pady=(4, 0))
        risk = {'high': '高影响', 'medium': '需留意', 'low': '低影响'}.get(target.get('risk'), '需留意')
        state = (('约 ' if target.get('partialSize') else '') + size_text(target.get('bytes'))) if exists else '不可用'
        right = tk.Frame(card, bg=WHITE)
        right.pack(side='right', anchor='n', padx=(10, 0))
        label(right, risk, 9, AMBER if target.get('risk') == 'high' else GREEN, True).pack(anchor='e')
        label(right, state, 9, MUTED).pack(anchor='e', pady=(4, 0))

    def _toggle_target(self, target, value):
        position = self.scroll.canvas.yview()[0] if self.scroll else 0
        self.selections[target['id']] = value
        if value:
            for other in self.targets:
                if other['id'] in target.get('exclusiveWith', []) or target['id'] in other.get('exclusiveWith', []):
                    self.selections[other['id']] = False
        self.render()
        self.after_idle(lambda: self.scroll and self.scroll.canvas.yview_moveto(position))

    def _scan(self):
        self._work('正在扫描，可能需要一分钟…', 'scan', self._scan_done)

    def _scan_done(self, result):
        self.targets = result
        self.selections = {}
        self.result_text = f'扫描完成，发现 {sum(bool(x.get("exists")) for x in result)} 个存在的项目。'
        if self.view == 'clean': self.render()

    def _prepare_clean(self):
        ids = [t['id'] for t in self.targets if self.selections.get(t['id'])]
        if not ids:
            messagebox.showinfo('选择项目', '请先扫描并选择需要清理的项目。', parent=self)
            return
        self._work('正在重新核对清理范围…', 'prepare-clean', lambda d: self._confirm(d, 'clean', ids=ids), ids=ids)

    def _prepare_one_click(self):
        self._work_callable('正在扫描并准备一键操作…', lambda progress: workflow.prepare(self.core), self._review_one_click)

    def _review_one_click(self, plan):
        items = []
        if not plan['close'].get('empty'):
            items += ['【关闭浏览器】', *plan['close'].get('items', [])]
        items.append('【永久清理：无法通过本软件恢复】')
        if not plan['cleanup']:
            items.append('本次扫描没有可执行的清理项。')
        for target in plan['cleanup']:
            items.append(target['title'])
            items.extend('    ' + resource['displayPath'] for resource in target.get('resources', []) if resource.get('exists'))
        items.append('【执行设置】')
        for action in plan['settings']:
            recoverable = action['id'] in workflow.RESTORE_MAP and plan['baseline'].get(action['id']) is False
            note = '可尝试按本次备份恢复' if recoverable else '不能自动恢复到本次执行前'
            items.append(f'{action["title"]}（{note}）')
            items.append('    ' + action.get('description', ''))
        if plan['conflicts'] or plan['overlap']:
            items.append('【因冲突或重叠而跳过】')
            items.extend(f'{x["item"]["title"]}：{x["reason"]}' for x in plan['conflicts'] + plan['overlap'])
        if plan['unavailable']:
            items.append('【因安全限制而跳过】')
            items.extend(f'{x["title"]}：{x["blockedReason"]}' for x in plan['unavailable'])
        detail = ('会关闭所列浏览器，清理数据并逐项执行设置。清理的数据不创建备份，无法通过本软件恢复；'
                  '多数设置也不能恢复到原值。需要管理员授权时请按系统提示操作。')
        if ConfirmDialog(self, {'title': '确认一键启动', 'detail': detail, 'items': items}).result:
            self._work_callable('正在执行一键操作…', lambda progress: workflow.execute(self.core, plan, progress=progress),
                                lambda result: self._completed('one-click', result))

    def _prepare_one_click_restore(self):
        self._work_callable('正在检查可恢复的项目…', lambda progress: workflow.prepare_restore(self.core), self._review_one_click_restore)

    def _review_one_click_restore(self, plan):
        if plan.get('empty'):
            messagebox.showinfo('一键恢复', plan['message'], parent=self)
            return
        record = plan['record']
        cannot_restore = [x['title'] for x in record.get('cleanup', [])]
        cannot_restore += [x['title'] for x in record.get('actions', []) if not x.get('restoreEligible')]
        cannot_restore += [x['title'] + '（恢复记录已变化或不可读取）' for x in plan.get('unavailable', [])]
        if not plan['actions']:
            messagebox.showinfo('一键恢复', '本次记录中没有可自动恢复的设置。清理的数据没有备份，无法通过本软件恢复。'
                                + ('\n\n无法自动恢复：\n' + '\n'.join(cannot_restore) if cannot_restore else ''), parent=self)
            return
        items = ['【可尝试恢复】'] + [x['title'] for x in plan['actions']]
        if not plan['close'].get('empty'):
            items += ['【需要关闭的浏览器】', *plan['close'].get('items', [])]
        if cannot_restore:
            items += ['【无法自动恢复】', *cannot_restore]
        detail = ('仅尝试恢复本次一键操作新建恢复记录的 DNS 和浏览器定位语言设置。'
                  '清理的数据以及没有保存原值的设置无法自动恢复；恢复可能需要管理员授权。')
        if ConfirmDialog(self, {'title': '确认一键恢复', 'detail': detail, 'items': items}).result:
            self._work_callable('正在恢复可用项目…', lambda progress: workflow.restore(self.core, plan, progress=progress),
                                lambda result: self._completed('one-click-restore', result))

    def _render_privacy(self):
        browser_page = self.view == 'browser'
        page_actions = self._page_actions()
        if browser_page:
            self._header('CLAUDE WEB / BROWSER', '浏览器与 Claude 网页版', '管理浏览器定位、网络与站点数据相关设置，并按需恢复。', ('关闭浏览器', self._prepare_close))
        else:
            self._header('CLAUDE / SYSTEM', 'Claude 与系统设置', '管理 Claude 环境变量以及系统定位、DNS 与地区设置。')
        chosen = sum(bool(self.action_selections.get(action['id'])) for action in page_actions)
        self._stats([('可用项目', str(len(page_actions)), '按需选择'), ('已选项目', str(chosen), '仅执行本页所选'),
                     ('执行前', '再次确认', '冲突选项不可同时执行')])
        warning = ('Cookie 清理可能退出网站；定位和 WebRTC 设置可能影响地图与网页通话。'
                   if browser_page else 'DNS、定位、时区和区域变更可能影响网络连接或系统显示。')
        self._strip(self.page, '操作可能影响日常使用', warning)
        self._result()
        self._section('操作项目', '  ·  仅执行本页勾选的项目', ('执行本页所选', self._prepare_privacy))
        scroll = ScrollFrame(self.page)
        scroll.pack(fill='both', expand=True)
        self.scroll = scroll
        if not self.actions:
            self._empty(scroll.body, '正在读取设置', '请稍候，或检查本地核心是否可用。')
            return
        scroll.body.columnconfigure(0, weight=1, uniform='operations')
        scroll.body.columnconfigure(1, weight=1, uniform='operations')
        for index, (kind, title, description) in enumerate((
            ('settings', '设置', '启用或调整功能'),
            ('restore', '恢复', '恢复或解除已有设置'),
        )):
            column = tk.Frame(scroll.body, bg=BG)
            column.grid(row=0, column=index, sticky='nsew', padx=(0, 6) if index == 0 else (6, 0))
            heading = tk.Frame(column, bg=BG)
            heading.pack(fill='x', pady=(0, 10))
            label(heading, title, 12, INK, True).pack(side='left')
            label(heading, description, 9, MUTED).pack(side='left', padx=8)
            items = [a for a in page_actions if action_group(a)[1] == kind]
            if not items:
                empty = tk.Frame(column, bg=WHITE, padx=14, pady=18, highlightbackground=LINE, highlightthickness=1)
                empty.pack(fill='x')
                label(empty, '暂无项目', 9, MUTED).pack(anchor='w')
            for action in items:
                self._action_card(column, action)

    def _page_actions(self):
        return [action for action in self.actions if action_group(action)[0] == self.view]

    def _action_card(self, parent, action):
        card = tk.Frame(parent, bg=WHITE, padx=14, pady=12, highlightbackground=LINE, highlightthickness=1)
        card.pack(fill='x', pady=(0, 8))
        var = tk.BooleanVar(value=self.action_selections.get(action['id'], False))
        tk.Checkbutton(card, variable=var, bg=WHITE, activebackground=WHITE, selectcolor=WHITE,
                       command=lambda: self._toggle_action(action, var.get())).pack(side='left', anchor='n', padx=(0, 8))
        content = tk.Frame(card, bg=WHITE)
        content.pack(side='left', fill='x', expand=True)
        title = label(content, action['title'], 10, INK, True, wraplength=240, justify='left')
        title.pack(anchor='w', fill='x')
        description = label(content, action['description'], 9, MUTED, wraplength=240, justify='left')
        description.pack(anchor='w', fill='x', pady=(4, 0))
        content.bind('<Configure>', lambda event: (title.configure(wraplength=max(100, event.width - 10)),
                                                  description.configure(wraplength=max(100, event.width - 10))))
        badges = ('需要退出浏览器  ·  ' if action.get('requiresBrowserClosed') else '') + ('高影响' if action.get('risk') == 'high' else '需留意')
        label(content, badges, 9, AMBER if action.get('risk') == 'high' else GREEN).pack(anchor='w', pady=(6, 0))
        if action['id'] == 'install-adguard':
            tools = tk.Frame(content, bg=WHITE)
            tools.pack(anchor='w', pady=(6, 0))
            button(tools, '重新检测安装', self._retry_adguard, padx=5, pady=3).pack(side='left')
            button(tools, '打开配置导入页', self._open_adguard_url, padx=5, pady=3).pack(side='left', padx=4)

    def _toggle_action(self, action, value):
        position = self.scroll.canvas.yview()[0] if self.scroll else 0
        self.action_selections[action['id']] = value
        if value:
            for other in self.actions:
                if other['id'] in action.get('exclusiveWith', []) or action['id'] in other.get('exclusiveWith', []):
                    self.action_selections[other['id']] = False
        self.render()
        self.after_idle(lambda: self.scroll and self.scroll.canvas.yview_moveto(position))

    def _retry_adguard(self):
        self._work('正在检查 AdGuard…', 'adguard-retry',
                   lambda rows: messagebox.showinfo('扩展检测结果', '\n'.join(f"{x.get('browser')}：{x.get('status')} {x.get('message', '')}" for x in rows), parent=self))

    def _open_adguard_url(self):
        self._work('正在准备导入页…', 'adguard-url', lambda url: webbrowser.open(url))

    def _prepare_privacy(self):
        ids = [a['id'] for a in self._page_actions() if self.action_selections.get(a['id'])]
        if not ids:
            messagebox.showinfo('选择设置', '请在本页选择至少一项操作。', parent=self)
            return
        self._work('正在核对设置…', 'prepare-privacy', lambda d: self._confirm(d, 'privacy', ids=ids), ids=ids)

    def _prepare_close(self):
        self._work('正在检查浏览器…', 'prepare-close', lambda d: self._confirm(d, 'close'))

    def _render_recovery(self):
        self._header('NETWORK RECOVERY', '恢复网络连接', '检测并恢复澄界造成的 DNS 改动，或失效的本机代理开关。', ('↻   重新检测', self._inspect))
        self._strip(self.page, '只处理可以识别的问题', '保留代理软件、节点和订阅；执行前会再次核对网络状态。')
        self._result()
        self._section('网络诊断', '  ·  先检测，再决定是否恢复')
        if not self.recovery:
            self._empty(self.page, '尚未检测网络', '点击右上角“重新检测”查看 DNS 与系统代理状态。')
            return
        dns = self.recovery.get('dns', {})
        proxy = self.recovery.get('proxy', {})
        for title, bad, detail in [
            ('DNS 防泄漏设置', dns.get('needsRecovery'), '检查本工具的 DNS 服务、网卡地址与防火墙规则。'),
            ('系统代理', proxy.get('canRepairAutomatically'), '仅检测失效的本机 HTTP / HTTPS 代理；其他代理配置保持不变。'),
        ]:
            card = tk.Frame(self.page, bg=WHITE, padx=20, pady=18, highlightbackground=LINE, highlightthickness=1)
            card.pack(fill='x', pady=(0, 10))
            label(card, '需处理' if bad else '未发现可恢复问题', 9, AMBER if bad else GREEN, True).pack(side='right')
            label(card, title, 12, INK, True).pack(anchor='w')
            label(card, detail, 9, MUTED).pack(anchor='w', pady=(6, 0))
        if proxy.get('canRepairAutomatically'):
            tk.Checkbutton(self.page, text='同时关闭已失效的本机代理开关', variable=self.repair_proxy,
                           bg=BG, activebackground=BG, fg=INK, font=(FONT, 10)).pack(anchor='w', pady=10)
        if self.recovery.get('hasRecoverableIssue'):
            button(self.page, '核对并恢复网络', self._prepare_recovery, primary=True).pack(anchor='w', pady=10)
        label(self.page, self.recovery.get('summary', ''), 9, MUTED, wraplength=830, justify='left').pack(anchor='w', pady=(8, 0))

    def _inspect(self):
        self._work('正在检测网络…', 'inspect-recovery', self._inspect_done)

    def _inspect_done(self, result):
        self.recovery = result
        if self.view == 'recovery': self.render()

    def _prepare_recovery(self):
        value = self.repair_proxy.get()
        self._work('正在核对网络状态…', 'prepare-recovery', lambda d: self._confirm(d, 'recover', repairProxy=value), repairProxy=value)

    def _confirm(self, data, command, **payload):
        if data.get('empty'):
            messagebox.showinfo('检查结果', data.get('message', '无需执行。'), parent=self)
            return
        if ConfirmDialog(self, data).result:
            self._work('正在执行，请稍候…', command, lambda result: self._completed(command, result, payload),
                       **payload, token=data['token'], acknowledged=True)

    def _completed(self, command, result, payload=None):
        rows = result.get('results', [])
        if rows:
            summaries = []
            for row in rows:
                name = row.get('title') or next((a['title'] for a in self.actions if a['id'] == row.get('id')), row.get('id', '项目'))
                states = {'cleaned': '已清理', 'completed': '已完成', 'failed': '失败', 'partial': '部分完成', 'skipped': '已跳过', 'missing': '不存在'}
                detail = row.get('message') or row.get('error') or states.get(row.get('status'), row.get('status', '已处理'))
                errors = [item.get('error') for item in row.get('resources', []) if item.get('error')]
                if errors:
                    detail += '：' + '；'.join(errors)
                summaries.append(f'{name}：{detail}')
            self.result_text = '\n'.join(summaries)
        else:
            self.result_text = result.get('message') or ('操作完成。' if result.get('status') in ('closed', 'completed') else str(result))
        if command == 'clean':
            self.targets = []
            self.selections = {}
            self.result_text += '\n请重新扫描以刷新结果。'
        if command == 'one-click':
            self.targets = []
            self.selections = {}
            self.result_text += '\n清理数据未备份；仅有备份的部分设置可尝试通过一键恢复还原。'
        if command == 'privacy':
            for action_id in (payload or {}).get('ids', []):
                self.action_selections.pop(action_id, None)
        if command == 'recover': self.recovery = None
        self.render()
        self._show_result_details()


def main():
    ClearspaceApp().mainloop()
