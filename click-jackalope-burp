# -*- coding: utf-8 -*-
# click_jackalope_burp.py
# Click-Jackalope – Clickjacking POC Generator for Burp

from java.awt import BorderLayout, FlowLayout, Desktop
from java.awt.event import ActionListener
from javax.swing import (
    JPanel,
    JLabel,
    JTextField,
    JButton,
    JFileChooser,
    JScrollPane,
    JTextArea,
    JOptionPane,
    JMenuItem,
)
from java.net import URI
from java.io import File, FileWriter, IOException
from java.lang import Runtime, System, Thread, Runnable
from burp import IBurpExtender, ITab, IContextMenuFactory

# Import unloading handler
try:
    from burp import IExtensionUnloadingHandler
    HAS_UNLOAD = True
except ImportError:
    HAS_UNLOAD = False
    IExtensionUnloadingHandler = object  # dummy base


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, ActionListener, IExtensionUnloadingHandler):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Click-Jackalope")
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()

        # main panel
        self._panel = JPanel(BorderLayout())

        # top controls
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("Target URL:"))
        self.url_field = JTextField(60)
        top.add(self.url_field)

        top.add(JLabel("Filename:"))
        self.file_field = JTextField("clickjack_test.html", 20)
        top.add(self.file_field)

        self.generate_btn = JButton("Generate", actionPerformed=self.actionPerformed)
        self.open_btn = JButton("Generate & Open", actionPerformed=self.actionPerformed)
        self.save_btn = JButton("Save As...", actionPerformed=self.actionPerformed)
        top.add(self.generate_btn)
        top.add(self.open_btn)
        top.add(self.save_btn)

        self._panel.add(top, BorderLayout.NORTH)

        # preview
        self.preview = JTextArea(12, 120)
        self.preview.setEditable(False)
        sp = JScrollPane(self.preview)
        self._panel.add(sp, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

        # register unload handler only if available
        if HAS_UNLOAD:
            callbacks.registerUnloadingHandler(self)

        self.log("Click-Jackalope loaded. Unload handler: %s" % ("enabled" if HAS_UNLOAD else "not available"))

    # ITab
    def getTabCaption(self):
        return "Click-Jackalope"

    def getUiComponent(self):
        return self._panel

    # Unloading
    def extensionUnloaded(self):
        self.log("Click-Jackalope unloaded.")

    # context menu
    def createMenuItems(self, invocation):
        msgs = invocation.getSelectedMessages()
        if msgs is None or len(msgs) == 0:
            return None
        item = JMenuItem(
            "Create Click-Jackalope POC",
            actionPerformed=lambda ev: self._create_from_selection(invocation),
        )
        return [item]

    def _create_from_selection(self, invocation):
        msgs = invocation.getSelectedMessages()
        if msgs is None or len(msgs) == 0:
            JOptionPane.showMessageDialog(
                self._panel,
                "No requests selected.",
                "Click-Jackalope",
                JOptionPane.WARNING_MESSAGE,
            )
            return

        msg = msgs[0]
        try:
            analyzed = self._helpers.analyzeRequest(msg)
            url = analyzed.getUrl()
            if url is None:
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Could not get URL from selection.",
                    "Click-Jackalope",
                    JOptionPane.WARNING_MESSAGE,
                )
                return

            url_str = url.toString()
            self.url_field.setText(url_str)

            host = url.getHost()
            if host is None:
                fname = "clickjack_test.html"
            else:
                fname = "clickjack_%s.html" % host.replace(":", "_")
            self.file_field.setText(fname)

            html = self._make_html(url_str)
            self.preview.setText(html)
            self._prompt_save_and_write(html, fname)
        except Exception as e:
            self.log("Error creating POC from selection: %s" % str(e))
            JOptionPane.showMessageDialog(
                self._panel,
                "Error: %s" % str(e),
                "Click-Jackalope",
                JOptionPane.ERROR_MESSAGE,
            )

    # button actions
    def actionPerformed(self, event):
        src = event.getSource()
        if src == self.generate_btn:
            self._handle_generate(False)
        elif src == self.open_btn:
            self._handle_generate(True)
        elif src == self.save_btn:
            url = self.url_field.getText().strip()
            if url == "":
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Please enter a target URL first.",
                    "Click-Jackalope",
                    JOptionPane.WARNING_MESSAGE,
                )
                return
            html = self._make_html(url)
            self.preview.setText(html)
            self._prompt_save_and_write(html, None)

    def _handle_generate(self, open_after):
        url = self.url_field.getText().strip()
        filename = self.file_field.getText().strip()
        if url == "":
            JOptionPane.showMessageDialog(
                self._panel,
                "Please enter a target URL first.",
                "Click-Jackalope",
                JOptionPane.WARNING_MESSAGE,
            )
            return
        if filename == "":
            filename = "clickjack_test.html"

        html = self._make_html(url)
        self.preview.setText(html)

        try:
            outfile = self._write_to_cwd(html, filename)
            self.log("Wrote %s" % outfile.getAbsolutePath())
            JOptionPane.showMessageDialog(
                self._panel,
                "Wrote: %s" % outfile.getAbsolutePath(),
                "Click-Jackalope",
                JOptionPane.INFORMATION_MESSAGE,
            )
            if open_after:
                self._open_file_in_browser_bg(outfile)
        except Exception as e:
            self.log("Error writing file: %s" % str(e))
            JOptionPane.showMessageDialog(
                self._panel,
                "Error writing file: %s" % str(e),
                "Click-Jackalope",
                JOptionPane.ERROR_MESSAGE,
            )

    # simple HTML escape for untrusted URLs
    def _escape_html(self, s):
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace("\"", "&quot;")
             .replace("'", "&#x27;")
        )

    def _make_html(self, url):
        u = url.strip()
        if not (u.startswith("http://") or u.startswith("https://")):
            u = "https://" + u
        esc = self._escape_html(u)

        parts = [
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "  <meta charset=\"utf-8\" />",
            "  <title>Clickjacking test: iframe of " + esc + "</title>",
            "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />",
            "  <style>",
            "    body { margin: 0; display: flex; flex-direction: column; height: 100vh; font-family: sans-serif; }",
            "    header { padding: 8px 12px; background: #222; color: white; }",
            "    .frame-wrap { flex: 1; display: flex; align-items: center; justify-content: center; background: #eee; }",
            "    iframe { border: 4px solid #444; width: 90%; height: 90%; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }",
            "    footer { padding: 6px 12px; font-size: 12px; color: #444; background: #fafafa; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <header>Clickjacking test page -- embedded URL: " + esc + "</header>",
            "  <div class=\"frame-wrap\">",
            "    <iframe src=\"" + esc + "\" title=\"clickjacking-test\" sandbox=\"\"></iframe>",
            "  </div>",
            "  <footer>Generated by Click-Jackalope</footer>",
            "</body>",
            "</html>",
        ]
        return "\n".join(parts)

    def _write_to_cwd(self, html, filename):
        out = File(filename)
        fw = None
        try:
            fw = FileWriter(out)
            fw.write(html)
            fw.flush()
            return out
        finally:
            if fw is not None:
                try:
                    fw.close()
                except:
                    pass

    def _prompt_save_and_write(self, html, suggested_name):
        chooser = JFileChooser()
        if suggested_name:
            chooser.setSelectedFile(File(suggested_name))
        ret = chooser.showSaveDialog(self._panel)
        if ret == JFileChooser.APPROVE_OPTION:
            sel = chooser.getSelectedFile()
            try:
                fw = FileWriter(sel)
                fw.write(html)
                fw.flush()
                fw.close()
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Saved: %s" % sel.getAbsolutePath(),
                    "Click-Jackalope",
                    JOptionPane.INFORMATION_MESSAGE,
                )
                self.log("Saved POC to %s" % sel.getAbsolutePath())
                r = JOptionPane.showConfirmDialog(
                    self._panel,
                    "Open in default browser?",
                    "Open",
                    JOptionPane.YES_NO_OPTION,
                )
                if r == JOptionPane.YES_OPTION:
                    self._open_file_in_browser_bg(sel)
            except IOException as ioe:
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Error saving file: %s" % str(ioe),
                    "Click-Jackalope",
                    JOptionPane.ERROR_MESSAGE,
                )
                self.log("Error saving file: %s" % str(ioe))

    # run open in background to keep UI responsive
    def _open_file_in_browser_bg(self, f):
        ext = self

        class OpenTask(Runnable):
            def run(self_inner):
                try:
                    ext._open_file_in_browser(f)
                except Exception as e:
                    ext.log("Background open failed: %s" % str(e))

        t = Thread(OpenTask())
        t.setDaemon(True)
        t.start()

    def _open_file_in_browser(self, f):
        # 1) Java Desktop
        try:
            if Desktop.isDesktopSupported():
                Desktop.getDesktop().browse(f.toURI())
                self.log("Opened file in default browser: %s" % f.getAbsolutePath())
                return
        except Exception as de:
            self.log("Desktop.browse failed: %s" % str(de))

        # 2) Burp callback
        try:
            file_uri = f.toURI().toString()
            try:
                self._callbacks.openUrl(file_uri)
                self.log("Opened file via callbacks.openUrl: %s" % file_uri)
                return
            except Exception:
                self.log("callbacks.openUrl not available or failed.")
        except Exception as e:
            self.log("Building file URI failed: %s" % str(e))

        # 3) OS fallback
        os_name = None
        try:
            os_name = System.getProperty("os.name").lower()
        except Exception:
            pass

        try:
            if os_name and "mac" in os_name:
                Runtime.getRuntime().exec(["open", f.getAbsolutePath()])
                self.log("Opened file with 'open': %s" % f.getAbsolutePath())
                return
            if os_name and "win" in os_name:
                Runtime.getRuntime().exec(["cmd", "/c", "start", "", f.getAbsolutePath()])
                self.log("Opened file with 'start': %s" % f.getAbsolutePath())
                return
            Runtime.getRuntime().exec(["xdg-open", f.getAbsolutePath()])
            self.log("Opened file with 'xdg-open': %s" % f.getAbsolutePath())
            return
        except Exception as pe:
            self.log("OS-level open failed: %s" % str(pe))

        # 4) last resort
        JOptionPane.showMessageDialog(
            self._panel,
            "File saved to: %s\nCould not automatically open it." % f.getAbsolutePath(),
            "Click-Jackalope",
            JOptionPane.INFORMATION_MESSAGE,
        )

    def log(self, msg):
        try:
            self._stdout.println("[Click-Jackalope] " + msg)
        except:
            pass
