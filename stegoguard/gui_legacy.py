"""Классический Tkinter-интерфейс СтегоВизор (резервный вариант без customtkinter)."""
from __future__ import annotations
import os, queue, threading
from typing import Dict, List, Optional
from . import __app_name__, __version__
from .analyzer import Analyzer
from .config import Config
from .utils import collect_files, human_bytes

PALETTE = {"CLEAN":"#e8f5ee", "SUSPICIOUS":"#fff4dc", "STEGO_DETECTED":"#fde9e7", "ERROR":"#edf0f4"}

def run_gui(cfg: Optional[Config] = None) -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    cfg = cfg or Config(); analyzer = Analyzer(cfg)
    root = tk.Tk(); root.title(f"{__app_name__} · {__version__}"); root.geometry("1240x790"); root.minsize(980, 620)
    root.configure(bg="#f3f6fa")
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except tk.TclError: pass
    style.configure("TFrame", background="#f3f6fa")
    style.configure("Header.TFrame", background="#14243a")
    style.configure("Header.TLabel", background="#14243a", foreground="#ffffff", font=("Segoe UI", 17, "bold"))
    style.configure("Sub.TLabel", background="#14243a", foreground="#b9c8da", font=("Segoe UI", 9))
    style.configure("TButton", font=("Segoe UI", 9), padding=(12, 8), background="#ffffff")
    style.configure("Accent.TButton", background="#1769aa", foreground="#ffffff", font=("Segoe UI", 9, "bold"))
    style.map("Accent.TButton", background=[("active", "#0e548e")])
    style.configure("Treeview", font=("Segoe UI", 9), rowheight=30, background="#ffffff", fieldbackground="#ffffff")
    style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=8, background="#e7edf4")
    style.configure("TLabelframe", background="#f3f6fa", bordercolor="#d8e0e9")
    style.configure("TLabelframe.Label", background="#f3f6fa", foreground="#34465b", font=("Segoe UI", 9, "bold"))

    results: Dict[str, Dict] = {}; files: List[str] = []; q: queue.Queue = queue.Queue(); busy = tk.BooleanVar(value=False)
    header = ttk.Frame(root, style="Header.TFrame", padding=(22, 16)); header.pack(fill="x")
    ttk.Label(header, text="СтегоВизор", style="Header.TLabel").pack(anchor="w")
    ttk.Label(header, text="Локальный анализ файлов · обработка без браузера и сетевых подключений", style="Sub.TLabel").pack(anchor="w", pady=(3,0))
    toolbar = ttk.Frame(root, padding=(16, 12)); toolbar.pack(fill="x")
    rob_var=tk.BooleanVar(value=False); att_var=tk.BooleanVar(value=False); pdf_password=tk.StringVar(value="")
    def _add(paths):
        added=0
        for p in paths:
            if p not in files and os.path.isfile(p):
                files.append(p); tree.insert("", "end", iid=p, values=(os.path.basename(p), "В очереди", "—", "—", "—", "—")); added+=1
        status.set(f"В очереди: {len(files)} файлов" if added else f"Файлов в очереди: {len(files)}")
    def add_files():
        selected=filedialog.askopenfilenames(filetypes=[("Поддерживаемые файлы", "*.png *.apng *.jpg *.jpeg *.bmp *.tif *.tiff *.webp *.gif *.pdf"),("Все файлы", "*.*")]); _add(list(selected))
    def add_folder():
        d=filedialog.askdirectory()
        if d: _add(collect_files([d], recursive=True))
    def clear():
        if busy.get(): return
        files.clear(); results.clear(); tree.delete(*tree.get_children()); details.delete("1.0","end"); status.set("Очередь очищена")
    def worker(paths, rob, att, password):
        for i,p in enumerate(paths,1):
            q.put(("progress",p,i,len(paths)))
            try: r=analyzer.analyze_file(p,robustness=rob,attacks=att,password=password or None)
            except Exception as exc: r={"file":p,"file_name":os.path.basename(p),"verdict":"ERROR","verdict_label":"Ошибка анализа","risk_score":None,"reasons":[str(exc)],"recommendations":[]}
            q.put(("result",p,r))
        q.put(("done",))
    def start():
        if busy.get(): return
        todo=[p for p in files if p not in results]
        if not todo: messagebox.showinfo(__app_name__,"Добавьте файлы для анализа или очистите очередь для повторной проверки."); return
        busy.set(True); pbar.configure(maximum=len(todo),value=0); threading.Thread(target=worker,args=(todo,rob_var.get(),att_var.get(),pdf_password.get()),daemon=True).start()
    def show(_evt=None):
        sel=tree.selection()
        if not sel or sel[0] not in results: return
        r=results[sel[0]]; details.delete("1.0","end")
        lines=[f"Файл: {r.get('file')}",f"Формат: {r.get('format') or ('PDF' if r.get('pdf') else 'PNG / растровое изображение')}",f"Заключение: {r.get('verdict_label')} · риск: {r.get('risk_score')}",f"Размер: {human_bytes(r.get('file_size') or 0)}",f"SHA-256: {r.get('sha256')}",""]
        if r.get("pdf"):
            p=r["pdf"]; h=p.get("hidden_text") or {}
            lines += [f"PDF: версия {p.get('version') or '?'}, страниц {p.get('pages')}, объектов {p.get('objects')}, потоков {p.get('streams')}",
                      f"Шифрование: {'да' if p.get('encrypted') else 'нет'}" + (" (расшифрован)" if p.get('decrypted') else ""),
                      f"JavaScript: {p.get('javascript_count',0)}, действий: {p.get('action_count',0)}, вложений: {p.get('attachments',0)}",
                      f"Изображений: {p.get('images',0)} (проанализировано {p.get('analyzed_images',0)}), макс. оценка вложения: {p.get('max_image_payload',0):.1%}",
                      f"Скрытых символов: {h.get('hidden_chars',0)}, подписей: {p.get('signature_count',0)}",
                      f"Данных после EOF: {p.get('trailing_bytes',0)} байт, обновлений: {p.get('incremental_updates',0)}",""]
        elif r.get("image"):
            im=r["image"]; lines.append(f"Изображение: {im.get('width')}×{im.get('height')}, {im.get('mode')}, {im.get('bit_depth')} бит")
        if r.get("parse_error"): lines.append(f"Разбор: {r['parse_error']}")
        if r.get("format_note"): lines.append(r["format_note"])
        lines += ["", "Основания:"] + [" • "+x for x in r.get("reasons",[])] + ["", "Рекомендации:"] + [" • "+x for x in r.get("recommendations",[])]
        details.insert("1.0","\n".join(lines))
    def save_report():
        sel=tree.selection()
        if not sel or sel[0] not in results: messagebox.showinfo(__app_name__,"Выберите проверенный файл"); return
        path=filedialog.asksaveasfilename(defaultextension=".html",filetypes=[("HTML", "*.html"),("JSON", "*.json")])
        if not path:return
        from .report import save_html,save_json
        (save_json if path.lower().endswith(".json") else save_html)(results[sel[0]],path)
        messagebox.showinfo(__app_name__,f"Отчёт сохранён локально:\n{path}")
    def save_all():
        if not results: messagebox.showinfo(__app_name__,"Нет результатов для экспорта"); return
        d=filedialog.askdirectory()
        if d:
            from .report import write_reports
            write_reports(list(results.values()),d); messagebox.showinfo(__app_name__,f"Отчёты сохранены:\n{d}")
    def do_sanitize():
        sel=tree.selection()
        if not sel: return
        src=sel[0]; ext=os.path.splitext(src)[1].lower()
        if ext==".pdf" or (src in results and results[src].get("format")=="PDF"):
            dst=filedialog.asksaveasfilename(defaultextension=".pdf",initialfile="clean_"+os.path.basename(src),filetypes=[("PDF", "*.pdf")])
            if dst:
                from .pdf_sanitizer import sanitize_pdf
                cfgp=cfg.pdf
                try: rep=sanitize_pdf(src,dst,password=pdf_password.get() or None,reencode_images=cfgp.sanitize_reencode_images,remove_hidden_text=cfgp.sanitize_remove_hidden_text)
                except Exception as exc: messagebox.showerror(__app_name__,f"Санитизация PDF не выполнена:\n{exc}"); return
                res=rep.get("verification") or {}
                messagebox.showinfo(__app_name__,f"Очищенная копия PDF сохранена:\n{dst}\n"
                                    f"Изображений перекодировано: {rep['images_reencoded']}\n"
                                    f"Скрытых символов удалено: {rep['removed_hidden_chars']}\n"
                                    f"Проверка результата: {res.get('verdict','—')}, остаточных находок: {len(res.get('residual_findings') or [])}")
            return
        if ext not in {".png", ".apng"}:
            messagebox.showwarning(__app_name__,"Санитизация доступна для PNG/APNG и PDF. Для других растровых форматов доступен анализ без изменения исходного файла."); return
        dst=filedialog.asksaveasfilename(defaultextension=".png",initialfile="clean_"+os.path.basename(src))
        if dst:
            from .sanitizer import sanitize
            rep=sanitize(src,dst); messagebox.showinfo(__app_name__,f"Очищенная копия сохранена:\n{dst}\nPSNR: {rep['psnr']:.2f} дБ")
    def do_extract_pdf():
        sel=tree.selection()
        if not sel: return
        src=sel[0]
        if os.path.splitext(src)[1].lower()!=".pdf" and not (src in results and results[src].get("format")=="PDF"):
            messagebox.showwarning(__app_name__,"Извлечение вложений доступно только для PDF."); return
        d=filedialog.askdirectory()
        if not d: return
        from .pdf_analyzer import extract_pdf_attachments
        try: written=extract_pdf_attachments(src,d,password=pdf_password.get() or None)
        except Exception as exc: messagebox.showerror(__app_name__,f"Не удалось извлечь вложения:\n{exc}"); return
        messagebox.showinfo(__app_name__,f"Извлечено файлов: {len(written)}\n{d}")
    for label,cmd,sty in [("＋ Добавить файлы",add_files,"TButton"),("▣ Добавить папку",add_folder,"TButton"),("▶ Запустить анализ",start,"Accent.TButton"),("Очистить",clear,"TButton"),("Отчёт",save_report,"TButton"),("Экспорт всех",save_all,"TButton"),("Санитизация (CDR)",do_sanitize,"TButton"),("Вложения PDF",do_extract_pdf,"TButton")]: ttk.Button(toolbar,text=label,command=cmd,style=sty).pack(side="left",padx=(0,6))
    options=ttk.Frame(root,padding=(18,0,18,10)); options.pack(fill="x")
    ttk.Checkbutton(options,text="Оценивать стойкость (дольше)",variable=rob_var).pack(side="left",padx=(0,18)); ttk.Checkbutton(options,text="Проверять живучесть канала",variable=att_var).pack(side="left",padx=(0,18))
    ttk.Label(options,text="Пароль PDF:").pack(side="left",padx=(0,4)); ttk.Entry(options,textvariable=pdf_password,show="*",width=18).pack(side="left")
    content=ttk.Frame(root,padding=(16,0,16,8)); content.pack(fill="both",expand=True)
    split=ttk.Panedwindow(content,orient="vertical"); split.pack(fill="both",expand=True)
    cols=("file","verdict","risk","payload","findings","iss"); tree=ttk.Treeview(split,columns=cols,show="headings",selectmode="browse")
    for c,t,w in zip(cols,("Файл","Заключение","Риск","Доля вложения","Находки","ИСС"),(360,290,75,120,90,75)):
        tree.heading(c,text=t); tree.column(c,width=w,anchor="w")
    for v,col in PALETTE.items(): tree.tag_configure(v,background=col)
    tree.bind("<<TreeviewSelect>>",show); split.add(tree,weight=3)
    detail_frame=ttk.LabelFrame(split,text="Карточка результата",padding=8); details=tk.Text(detail_frame,height=12,font=("Consolas",9),wrap="word",bg="#ffffff",fg="#263445",relief="flat",padx=10,pady=8); details.pack(fill="both",expand=True); split.add(detail_frame,weight=2)
    footer=ttk.Frame(root,padding=(18,8)); footer.pack(fill="x"); status=tk.StringVar(value="Добавьте PDF или растровые файлы для локального анализа")
    ttk.Label(footer,textvariable=status).pack(side="left"); pbar=ttk.Progressbar(footer,length=260,mode="determinate"); pbar.pack(side="right")
    def poll():
        try:
            while True:
                msg=q.get_nowait()
                if msg[0]=="progress": status.set(f"Анализ {msg[2]}/{msg[3]}: {os.path.basename(msg[1])}"); tree.set(msg[1],"verdict","Проверяется…")
                elif msg[0]=="result":
                    _,p,r=msg; results[p]=r; st=r.get("statistics") or {}; rob=r.get("robustness") or {}; pdf=r.get("pdf") or {}; findings=(r.get("structure") or {}).get("findings",[])
                    payload=(st.get('effective_payload') if st else pdf.get('max_image_payload'))
                    tree.item(p,values=(r.get("file_name"),r.get("verdict_label"),r.get("risk_score") if r.get("risk_score") is not None else "—",f"{payload:.1%}" if payload is not None else "—",len([f for f in findings if f.get("severity")!="info"]),f"{rob['stability_index']:.1f}" if rob.get("supported") else "—"),tags=(r.get("verdict","ERROR"),)); pbar.step(1)
                elif msg[0]=="done":
                    busy.set(False); counts={}
                    for r in results.values(): counts[r.get("verdict_label","Ошибка")]=counts.get(r.get("verdict_label","Ошибка"),0)+1
                    status.set("Готово · "+" / ".join(f"{k}: {v}" for k,v in counts.items()))
        except queue.Empty: pass
        root.after(150,poll)
    root.after(150,poll); root.mainloop()
