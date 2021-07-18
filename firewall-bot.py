# -*- coding: utf-8 -*-
import gettext
import os
import platform
import re
import socket
from contextlib import suppress

import segno
import ufw.common as ufwc
import ufw.frontend as ufwf
import ufw.parser as ufwp
import ufw.util as ufwu
from deltabot import DeltaBot
from deltabot.hookspec import deltabot_hookimpl
from deltachat import Chat, Contact, Message

version = "0.8"


# >>> HOOKS


@deltabot_hookimpl
def deltabot_init(bot):
    global dbot
    dbot = bot
    bot.commands.unregister(name="/set")
    menu()


@deltabot_hookimpl
def deltabot_start(bot: DeltaBot, chat=Chat):
    """
    Runs every time the bot starts and checks if it was already set up.
    Prints a QR-code to terminal. Admins can scan it and get added to an admingroup.
    Where Members can send commands to the bot.
    """
    chat = None
    if dbot.get("issetup") == "yes!" and dbot.get("admgrpid") != "":
        chat = dbot.account.get_chat_by_id(int(dbot.get("admgrpid")))
        print("Admingroup found\n")
    else:
        dbot.logger.warn("Creating a firewall-bot group")
        chat = dbot.account.create_group_chat(
            f"Admin group on {host}", contacts=[], verified=True
        )
        dbot.set("admgrpid", chat.id)
        dbot.set("issetup", "yes!")
    if ufwu.get_ppid(os.getpid()) != 1:
        qr = segno.make(chat.get_join_qr())
        print(
            "\nPlease scan this qr code with your deltachat client to join a verified firewall-bot group chat:\n\n"
        )
        qr.terminal()
    #print(dbot.list_settings("global"))
    #print(dbot.account.get_info())
    #dbot.set("bigmac", "deltachat.bx5i8n@jhlndwhr.com")
    print(dbot.get("bigmac"))


# >>> UTILITIES
alert = []
hlp = {
    "info": "Shows system info.",
    "status": "Get and set firewall status.",
    "policy": "Get and set default policies.",
    "rules": "Get and set firewall rules.",
    "guide": "Build rules step-by-step.",
    "service": "Show listening services.",
    "scan": "Perform port-scans. (coming soon)",
}


def verify(message):
    if message.chat.is_group() and int(dbot.get("admgrpid")) == message.chat.id:
        if message.chat.is_protected():
            return True
    dbot.logger.error("recieved message from outside admingroup chat.")
    dbot.logger.error(f"sender: {message.get_sender_contact().addr}")
    dbot.logger.error(f"chat: {message.chat.get_name()}")
    dbot.logger.error(f"message: {message.text}")
    return False


def menu():
    for k, v in {"help": ("help", "h", "?"), "eval(c)": hlp.keys()}.items():
        for c in v:
            with suppress(Exception):
                dbot.commands.unregister(name=f"/{c}")
            dbot.commands.register(name=f"/{c}", func=eval(k))


def menu_off():
    for d in [("help", "h", "?"), hlp.keys()]:
        for c in d:
            with suppress(Exception):
                dbot.commands.unregister(name=f"/{c}")
            dbot.commands.register(name=f"/{c}", func=fake)


def fake(command, replies):
    """."""
    if not verify(command.message):
        return
    if command.message.text[1:].split()[0] in ("help", "h", "?"):
        replies.add("⚠️ not available in guided mode")
    else:
        replies.add("⚠️ quit guided mode first")


def fw():
    gettext.install(ufwc.programName)
    frontend = ufwf.UFWFrontend(dryrun=False)
    return (frontend, frontend.backend)


def clear_cmd():
    for c in ("/", "start", "stop", "reset", "move", "del"):
        with suppress(Exception):
            dbot.commands.unregister(name=f"/{c}")


def help(command, replies):
    """."""
    if not verify(command.message):
        return
    x = []
    for c, d in hlp.items():
        x.append(f"🔅 /{c}\n{d}")
    x.append("🔅 /help /h /?\nInvoke this menu.")
    x = "\n\n".join(x)
    replies.add(f"🌐 MENU\n\n{x}")


# >>> INFO


def info(command, replies):
    """."""
    if not verify(command.message):
        return
    host = socket.gethostname()
    ip = socket.gethostbyname(socket.getfqdn())
    lin = platform.platform()
    replies.add(
        f"🌐 SYSTEM\n🔹 Hostname:  '{host}'\n🔹 IP-address:  '{ip}'\n🔹 fwbot version:  '{version}'\n🔹 OS:  '{lin}'"
    )


# >>> STATUS


def status(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    x = "active"
    for c in ("input", "output"):
        if ufwu.cmd([fw()[1].iptables, "-L", "ufw-user-%s" % (c), "-n"])[0] == 1:
            x = "inactive"
    if x == "active":
        dbot.commands.register(name="/stop", func=status_stop)
        replies.add(f"🌐 STATUS\n🔹 firewall:  'active'\n\n🔺 /stop\nStopps firewall and disables startup on boot.")
    else:
        dbot.commands.register(name="/start", func=status_start)
        replies.add(f"🌐 STATUS\n🔹 firewall:  'inactive'\n\n🔺 /start\nStarts firewall and enables startup on boot.")


def status_start(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    fw()[0].set_enabled(True)
    status(command, replies)


def status_stop(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    fw()[0].set_enabled(False)
    status(command, replies)


# >>> POLICY


def policy(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    x = (fw()[1]._get_default_policy(), fw()[1]._get_default_policy("output"))
    dbot.commands.register(name="//", func=policy_set)
    replies.add(
        f"{alrt}🌐 POLICIES\n🔹 incoming:  '{x[0]}'\n🔹 outgoing:  '{x[1]}'\n\n🔺 //  *action*  *action*\nSet the default action for incoming (1st) and outgoing (2nd) traffic to allow, deny or reject."
    )


def policy_set(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 2:
        alert.append("⚠️ expects two arguments")
    elif not set(pl).issubset({"reject", "allow", "deny"}):
        alert.append("⚠️ arguments must be reject, allow or deny")
    else:
        for c, d in zip(("incoming", "outgoing"), pl):
            fw()[1].set_default_policy(d, c)
        if fw()[1].is_enabled():
            fw()[1].stop_firewall()
            fw()[1].start_firewall()
    policy(command, replies)


# >>> RULES


def rules(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    x = []
    for c in fw()[1].get_rules():
        x.append(f"🔹 {len(x) + 1}:  '{ufwp.UFWCommandRule.get_command(c)}'")
    dbot.commands.register(name="//", func=rules_pl)
    y = ["\n\n", "", ""]
    if len(x) > 0:
        dbot.commands.register(name="/del", func=rules_del)
        y[2] = "\n🔺 /del  *rulenumber*\nDelete a rule.\n"
    if len(x) > 1:
        dbot.commands.register(name="/reset", func=rules_rst)
        y[0] = "\n🔺 /reset\nDelete all rules shown above.\n"
        dbot.commands.register(name="/move", func=rules_mv)
        y[
            1
        ] = "\n🔺 /move  *rulenumber*  *position*\nMoves an existing rule to a specific position. (experimental)\n"
    x = "\n".join(x)
    replies.add(
        f"{alrt}🌐 RULES\n{x}\n\n🔺 //  *ufw-command*\nSpecify a valid ufw-command to add or insert allow/deny/reject/limit-rules or to delete rules.\n{y[2]}{y[0]}{y[1]}\n📖 rule syntax: https://is.gd/18ivdz"
    )


# maybe add check for proto any and port any and remove them as they will raise an ufw ERROR because of a long time unfixed bug
def rules_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    opt = ("allow", "deny", "reject", "limit", "delete", "insert")
    clear_cmd()
    p = ufwp.UFWParser()
    for c in opt:
        p.register_command(ufwp.UFWCommandRule(c))
    if "comment" in command.payload:
        plx = re.split("comment", command.payload)
        pl = [c for c in plx[0].split() if c.strip()]
        cmt = [c for c in plx[1].split() if c.strip()]
    else:
        pl = [c for c in command.payload.split() if c.strip()]
        cmt = []
    if len(pl) < 2:
        alert.append("⚠️ expects arguments")
    elif pl[0] not in opt:
        alert.append("⚠️ invalid *action*")
    # add elif for insert but invalid action - length of pl has to be checked
    else:
        if cmt:
            pl.append("comment")
            pl.append(" ".join(cmt))
        try:
            pr = p.parse_command(pl)
            print(pr)
            fw()[0].do_action(
                pr.action, pr.data.get("rule", ""), pr.data.get("iptype", ""), True
            )
        except Exception as xcp:
            alert.append(f"⛔️ ufw exception: {xcp}")
        except:
            alert.append(f"📛 ufw error")
    rules(command, replies)


def rules_del(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    p = ufwp.UFWParser()
    p.register_command(ufwp.UFWCommandRule("delete"))
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not pl[0].isnumeric():
        alert.append("⚠️ argument must be numeric")
    elif not 0 < int(pl[0]) <= fw()[1].get_rules_count(False):
        alert.append("⚠️ argument must be valid rulenumber")
    else:
        try:
            pr = p.parse_command(["delete", pl[0]])
            fw()[0].do_action(
                pr.action, pr.data.get("rule", ""), pr.data.get("iptype", ""), True
            )
        except Exception as xcp:
            alert.append(f"⛔️ ufw exception: {xcp}")
        except:
            alert.append(f"📛 ufw error")
    rules(command, replies)


def rules_rst(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    p = ufwp.UFWParser()
    p.register_command(ufwp.UFWCommandRule("delete"))
    while fw()[1].get_rules_count(False) > 0:
        try:
            pr = p.parse_command(["delete", "1"])
            fw()[0].do_action(
                pr.action, pr.data.get("rule", ""), pr.data.get("iptype", ""), True
            )
        except Exception as xcp:
            alert.append(f"⛔️ ufw exception: {xcp}")
        except:
            alert.append(f"📛 ufw error")
    rules(command, replies)


# move muss überarbeitet werden, ggf. statt position angeben, ob vor oder hinter einer bestimmten rule
def rules_mv(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    p = ufwp.UFWParser()
    for c in ("delete", "insert"):
        p.register_command(ufwp.UFWCommandRule(c))
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 2:
        alert.append("⚠️ expects two arguments")
    elif not all([c.isnumeric() for c in pl]):
        alert.append("⚠️ arguments must be numeric")
    else:
        x = fw()[1].get_rules_count(False)
        y = int(pl[0])
        z = int(pl[1])
        if not (y != z and 0 < y <= x and 0 < z <= x):
            # could be more elaborate
            alert.append("⚠️ invalid argument(s)")
        else:
            rle = ufwp.UFWCommandRule.get_command(fw()[1].get_rules()[y - 1]).split()
            try:
                pr = p.parse_command(["delete"] + rle)
                fw()[0].do_action(
                    pr.action,
                    pr.data.get("rule", ""),
                    pr.data.get("iptype", ""),
                    True,
                )
            except Exception as xcp:
                alert.append(f"⛔️ ufw exception: {xcp}")
            except:
                alert.append(f"📛 ufw error")
            else:
                w = 0
                if y < z:
                    w = 1
                try:
                    pr = p.parse_command(["insert"] + [str(z - w)] + rle)
                    fw()[0].do_action(
                        pr.action,
                        pr.data.get("rule", ""),
                        pr.data.get("iptype", ""),
                        True,
                    )
                except Exception as xcp:
                    alert.append(f"⛔️ ufw exception: {xcp}")
                except:
                    alert.append(f"📛 ufw error")
    rules(command, replies)


# >>> SERVICE
serv = []
dels = []


def service(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    try:
        netstat = ufwu.parse_netstat_output(fw()[1].use_ipv6())
    except Exception:
        return
    listeners = []
    rules = fw()[1].get_rules()
    l4_protocols = list(netstat.keys())
    l4_protocols.sort()
    for transport in l4_protocols:
        if not fw()[1].use_ipv6() and transport in ["tcp6", "udp6"]:
            continue
        ports = list(netstat[transport].keys())
        ports.sort()
        for port in ports:
            for item in netstat[transport][port]:
                listen_addr = item["laddr"]
                if listen_addr.startswith("127.") or listen_addr.startswith("::1"):
                    continue
                ifname = ""
                if listen_addr == "0.0.0.0" or listen_addr == "::":
                    listen_addr = "%s/0" % (item["laddr"])
                    addr = "*"
                else:
                    ifname = ufwu.get_if_from_ip(listen_addr)
                    addr = listen_addr
                application = os.path.basename(item["exe"])
                rule = ufwc.UFWRule(
                    action="allow",
                    protocol=transport[:3],
                    dport=port,
                    dst=listen_addr,
                    direction="in",
                    forward=False,
                )
                rule.set_v6(transport.endswith("6"))
                if ifname != "":
                    rule.set_interface("in", ifname)
                rule.normalize()
                matching_rules = {}
                matching = fw()[1].get_matching(rule)
                if len(matching) > 0:
                    for rule_number in matching:
                        if rule_number > 0 and rule_number - 1 < len(rules):
                            rule = fw()[1].get_rule_by_number(rule_number)
                            rule_command = ufwp.UFWCommandRule.get_command(rule)
                            matching_rules[rule_number] = rule_command
                listeners.append(
                    (transport, addr, int(port), application, matching_rules)
                )
    x = []
    serv.clear()
    dels.clear()
    i = 0
    rl = False
    for c in listeners:
        z = c[1]
        if z == "*":
            z = "all"
        y = "None"
        if c[4]:
            y = []
            for k, v in c[4].items():
                dels.append(k)
                y.append(f"\t\t🔹 {k}:  '{v}'")
            y = "\n" + "\n".join(y)
            rl = True
        serv.append((c[0], c[1], c[2], c[3]))
        x.append(
            f"🔷 ID: {i}\n\t🔹 Service:  '{c[3]}'\n\t🔹 Protocol:  '{c[0]}'\n\t🔹 Port:  '{c[2]}'\n\t🔹 Address:  '{z}'\n\t🔹 Rules:  {y}"
        )
        i += 1
    if x:
        dbot.commands.register(name="//", func=service_pl)
        y = "\n\n"
        if rl:
            dbot.commands.register(name="/del", func=service_del)
            y = "\n🔺 /del  *rulenumber* \nDelete a corresponding rule.\n"
        x = "\n".join(x)
        replies.add(
            f"{alrt}🌐 SERVICES\n{x}\n\n🔺 //  *action*  *ID*\nAutomagically create a corresponding rule with action allow, deny or reject. This rule will match the service as closely as possible.\n{y}\nDepending on your default profile or before rules it might not be necessary to have explicit rules for every listener."
        )
    else:
        replies.add(f"{alrt}🌐 SERVICES\n\nNo listening services found.")


def service_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 2:
        alert.append("⚠️ expects two arguments")
    elif pl[0] not in ("allow", "deny", "reject"):
        alert.append("⚠️ 1st argument must be allow, deny or reject")
    elif not pl[1].isnumeric():
        alert.append("⚠️ 2nd argument must be numeric")
    elif not 0 <= int(pl[1]) < len(serv):
        alert.append("⚠️ 2nd argument must be valid ID")
    else:
        p = ufwp.UFWParser()
        p.register_command(ufwp.UFWCommandRule(pl[0]))
        ppll = [pl[0], f"{serv[int(pl[1])][2]}/{serv[int(pl[1])][0]}"]
        if serv[int(pl[1])][1] != "*":
            ppll = [
                pl[0],
                "to",
                serv[int(pl[1])][1],
                "port",
                str(serv[int(pl[1])][2]),
                "proto",
                serv[int(pl[1])][0],
            ]
        ppll.append("comment")
        ppll.append(f"auto for {serv[int(pl[1])][3]}")
        try:
            pr = p.parse_command(ppll)
            fw()[0].do_action(
                pr.action,
                pr.data.get("rule", ""),
                pr.data.get("iptype", ""),
                True,
            )
        except Exception as xcp:
            alert.append(f"⛔️ ufw exception: {xcp}")
        except:
            alert.append(f"📛 ufw error")
    service(command, replies)


def service_del(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not pl[0].isnumeric():
        alert.append("⚠️ argument must be numeric")
    elif int(pl[0]) not in dels:
        alert.append("⚠️ argument must be valid rulenumber")
    else:
        p = ufwp.UFWParser()
        p.register_command(ufwp.UFWCommandRule("delete"))
        try:
            pr = p.parse_command(["delete", pl[0]])
            fw()[0].do_action(
                pr.action, pr.data.get("rule", ""), pr.data.get("iptype", ""), True
            )
        except Exception as xcp:
            alert.append(f"⛔️ ufw exception: {xcp}")
        except:
            alert.append(f"📛 ufw error")
    service(command, replies)


# >>> GUIDE
gmd = ["append", "incoming", None, "any", "any", "tcp/udp", "any", None]
gmc = []


def guide_unreg(x=None):
    for c in (x, "b", "s", "/", "f", "d", "out", "src", "dst"):
        with suppress(Exception):
            dbot.commands.unregister(name=f"/{c}")


def guide_q(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc.clear()
    guide_unreg("q")
    menu()
    replies.add("⚠️ guided mode cancelled")


def guide_r(i):
    z = "Position Direction Action Source Destination Protocol Port(range)s Comment"
    x = []
    for c, d, e in zip(range(8), z.split(), gmc):
        y = "🔹 "
        if c == i and c < 8:
            y = "🔸 "
        x.append(f"{y}{d}:  '{e}'")
    return "\n".join(x)


def guide(command, replies):
    """."""
    if not verify(command.message):
        return
    txt = "This mode will guide you through the creation of a firewall rule. Below you will find a list of rules as well as all possible commands.\nOnce started, you will be presented with the new rule and its default values and an indicator for which value is currently being edited.\nIf available, you may choose  /s  (skip)  to advance to the next step (maintaining the current value or default).\nIf available, you may choose  /d  (default)  to set a value to its default and advance to the next step.\n To (re-)edit a (skipped) setting, use  /b  (back)  to go to the previous step.\nTo exit this mode at any time, use  /q  (quit)  - all settings done so far will be discarded.\n\nEach step will explain what is being edited as well as possible commands and arguments.\n(in addition to  /d  /b  /s  /q)."
    clear_cmd()
    menu_off()
    gmc.clear()
    for c in gmd:
        gmc.append(c)
    dbot.commands.register(name="/q", func=guide_q)
    dbot.commands.register(name="/s", func=guide_0)
    x = []
    for c in fw()[1].get_rules():
        x.append(f"🔹 {len(x) + 1}:  '{ufwp.UFWCommandRule.get_command(c)}'")
    x = "\n".join(x)
    replies.add(f"🌐 GUIDE\n{txt}\n\n🌐 RULES\n{x}\n\n🔺 /s  (start)\n🔺 /q  (quit)")


def guide_0(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    x = fw()[1].get_rules_count(False)
    y = "Allowed values for *position*:  1"
    if x > 1:
        y = f"Allowed values for *position*:  1  to  {x}"
    elif x == 0:
        y = "No rules set, can only append!"
    txt = f"Do you want to insert this rule at a specific position or append it at the end of all rules?\n(Default: append)\nRules are evaluated from top to bottom!\n\n{y}"
    guide_unreg()
    dbot.commands.register(name="/s", func=guide_1)
    #dbot.commands.register(name="//", func=guide_0_pl)
    d = ""
    z = ""
    if gmc[0] != gmd[0]:
        dbot.commands.register(name="/d", func=guide_0_def)
        d = "\n🔺 /d  (default)"
    if x != 0:
        dbot.commands.register(name="//", func=guide_0_pl)
        z = "\n🔺 //  *position*"
    replies.add(
        f"{alrt}🌐 GUIDE (1/8)\n{txt}\n\n{guide_r(0)}\n{z}{d}\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_0_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[0] = gmd[0]
    guide_1(command, replies)


def guide_0_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not pl[0].isnumeric():
        alert.append("⚠️ argument must be numeric")
    elif not 0 < int(pl[0]) <= fw()[1].get_rules_count(False):
        alert.append("⚠️ argument must be valid position")
    else:
        gmc[0] = pl[0]
        guide_1(command, replies)
        return
    guide_0(command, replies)


def guide_1(command, replies):
    """."""
    if not verify(command.message):
        return
    txt = "Do you want this rule to target traffic directed towards your system (incoming) or traffic originating from your system (outgoing)?\n(Default: incoming)\n\nDepending on the current setting, use  /out  or  /d  to switch between these options."
    guide_unreg()
    dbot.commands.register(name="/s", func=guide_2)
    dbot.commands.register(name="/b", func=guide_0)
    if gmc[1] == gmd[1]:
        dbot.commands.register(name="/out", func=guide_1_out)
        x = "\n🔺 /out"
    else:
        dbot.commands.register(name="/d", func=guide_1_def)
        x = "\n🔺 /d  (default)"
    replies.add(
        f"🌐 GUIDE (2/8)\n{txt}\n\n{guide_r(1)}\n{x}\n🔺 /b  (back)\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_1_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[1] = gmd[1]
    guide_2(command, replies)


def guide_1_out(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[1] = "outgoing"
    guide_2(command, replies)


def guide_2(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = "Which action would you like the rule to take for the targeted traffic?\nThis setting has no default value.\n\nAllowed values for *action*:\n・ allow\n    (traffic will be accepted)\n・ deny\n    (traffic will be discarded)\n・ reject\n    (traffic will be discarded and an error paket will be returned to the sender)"
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_1)
    dbot.commands.register(name="//", func=guide_2_pl)
    s = ""
    if gmc[2] != gmd[2]:
        dbot.commands.register(name="/s", func=guide_3)
        s = "\n🔺 /s  (skip)"
    replies.add(
        f"{alrt}🌐 GUIDE (3/8)\n{txt}\n\n{guide_r(2)}\n\n🔺 //  *action*\n🔺 /b  (back){s}\n🔺 /q  (quit)"
    )


def guide_2_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif pl[0] not in ("allow", "deny", "reject"):
        alert.append("⚠️ argument must be allow, deny or reject")
    else:
        gmc[2] = pl[0]
        guide_3(command, replies)
        return
    guide_2(command, replies)


def guide_3(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = "Do you want this rule to filter traffic originating from a specific source?\n(Default: any)\n\nAllowed values for *source*:\n・ host  (e.g. 8.8.8.8)\n・ network  (e.g. 8.8.8.8/24)"
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_2)
    dbot.commands.register(name="/s", func=guide_4)
    dbot.commands.register(name="//", func=guide_3_pl)
    d = ""
    if gmc[3] != gmd[3]:
        dbot.commands.register(name="/d", func=guide_3_def)
        d = "\n🔺 /d  (default)"
    replies.add(
        f"{alrt}🌐 GUIDE (4/8)\n{txt}\n\n{guide_r(3)}\n\n🔺 //  *source*{d}\n🔺 /b  (back)\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_3_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[3] = gmd[3]
    guide_4(command, replies)


def guide_3_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not ufwu.valid_address4(pl[0]):
        alert.append("⚠️ argument must be host or network")
    else:
        gmc[3] = pl[0]
        guide_4(command, replies)
        return
    guide_3(command, replies)


def guide_4(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = "Do you want this rule to filter traffic directed towards a specific destination?\n(Default: any)\n\nAllowed values for *destination*:\n・ host (e.g. 8.8.8.8)\n・ network (e.g. 8.8.8.8/24)"
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_3)
    dbot.commands.register(name="/s", func=guide_5)
    dbot.commands.register(name="//", func=guide_4_pl)
    d = ""
    if gmc[4] != gmd[4]:
        dbot.commands.register(name="/d", func=guide_4_def)
        d = "\n🔺 /d  (default)"
    replies.add(
        f"{alrt}🌐 GUIDE (5/8)\n{txt}\n\n{guide_r(4)}\n\n🔺 //  *destination*{d}\n🔺 /b  (back)\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_4_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[4] = gmd[4]
    guide_5(command, replies)


def guide_4_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not ufwu.valid_address4(pl[0]):
        alert.append("⚠️ argument must be host or network")
    else:
        gmc[4] = pl[0]
        guide_5(command, replies)
        return
    guide_4(command, replies)


def guide_5(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = "Would you like to restrict this rules filtering to a specific protocol?\n(Default: tcp and udp)\n\nAllowed values for *protocol*:\n・ tcp\n・ udp\n・ esp\n・ gre\n・ ah\n・ igmp\n・ ipv6\n\nWith the exception of default there are some restrictions:\n・ tcp and udp need specification of port(range)s.\n・ All other protocols do not allow port specification but need at least one of source/destination specified.\n(Please consult your favourite search engine to get information about these protocols)."
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_4)
    dbot.commands.register(name="/s", func=guide_6)
    dbot.commands.register(name="//", func=guide_5_pl)
    d = ""
    if gmc[5] != gmd[5]:
        dbot.commands.register(name="/d", func=guide_5_def)
        d = "\n🔺 /d  (default)"
    replies.add(
        f"{alrt}🌐 GUIDE (6/8)\n{txt}\n\n{guide_r(5)}\n\n🔺 //  *protocol*{d}\n🔺 /b  (back)\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_5_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[5] = gmd[5]
    guide_6(command, replies)


def guide_5_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in command.payload.split() if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif pl[0] not in ("tcp", "udp", "ah", "esp", "gre", "ipv6", "igmp"):
        alert.append("⚠️ argument must be tcp, udp, ah, esp, gre, ipv6 or igmp")
    else:
        gmc[5] = pl[0]
        guide_6(command, replies)
        return
    guide_5(command, replies)


def guide_5_other(replies):
    txt = f"For protocol {gmc[5]} you must choose source or destination!\nUse  /src  or  /dst  to jump back to those steps or  /b  to go back and change protocol."
    dbot.commands.register(name="/b", func=guide_5)
    dbot.commands.register(name="/src", func=guide_3)
    dbot.commands.register(name="/dst", func=guide_4)
    replies.add(
        f"🌐 GUIDE (6/8)\n{txt}\n\n{guide_r(5)}\n\n🔺 /src  (source)\n🔺 /dst  (destination)\n🔺 /b  (back)\n🔺 /q  (quit)"
    )


def guide_6(command, replies):
    """."""
    if not verify(command.message):
        return
    guide_unreg()
    if gmc[5] == gmd[5]:
        guide_6_both(replies)
    elif gmc[5] in ("tcp", "udp"):
        guide_6_one(replies)
    elif gmc[3] == gmd[3] and gmc[4] == gmd[4]:
        guide_5_other(replies)
    else:
        guide_6_other(replies)


def guide_6_one(replies):
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = f"For protocol {gmc[5]} you must choose port(range)s!\n\nAllowed values for *port(range)s*:\n・ a single port (e.g 80)\n・ multiple ports (e.g. 80,443)\n・ a portrange (e.g. 22:44)\n・ multiple portranges (e.g 22:44,55:77)\n・ any combination (e.g 80,55:77,22:44,443)"
    dbot.commands.register(name="/b", func=guide_5)
    dbot.commands.register(name="//", func=guide_6_one_pl)
    s = ""
    if gmc[6] != gmd[6]:
        dbot.commands.register(name="/s", func=guide_7)
        s = "\n🔺 /s  (skip)"
    replies.add(
        f"{alrt}🌐 GUIDE (7/8)\n{txt}\n\n{guide_r(6)}\n\n🔺 //  *port(range)s*\n🔺 /b  (back){s}\n🔺 /q  (quit)"
    )


# duplicates and ports inside a range are okay with ufw
def guide_6_one_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    rep = ""
    repp = ["⚠️ arguments for ports must be"]
    repr = ["⚠️ arguments for portranges must be"]
    pl = [c for c in re.split(",", command.payload) if c.strip()]
    port = [c for c in pl if ":" not in c]
    range = [c for c in pl if ":" in c]
    if port:
        if not all([c.isnumeric() for c in port]):
            repp.append("numeric")
        elif any([int(c) <= 0 or int(c) > 65535 for c in port]):
            repp.append("valid portnumbers")
    if range:
        for rng in range:
            rng_items = [c for c in re.split(":", rng) if c.strip()]
            if len(rng_items) != 2:
                repr.append("two numbers separated by ':'")
                break
            elif not all([c.isnumeric() for c in rng_items]):
                repr.append("numeric")
                break
            elif rng_items[1] == rng_items[0]:
                repr.append("two different portnumbers")
                break
            elif any([int(c) <= 0 or int(c) > 65535 for c in rng_items]):
                repr.append("valid portnumbers")
                break
            elif rng_items[1] < rng_items[0]:
                repr.append("smaller number first")
                break
    if len(repp) > 1 and len(repr) > 1:
        rep = f"{' '.join(repp)}\n{' '.join(repr)}"
    elif len(repp) > 1:
        rep = " ".join(repp)
    elif len(repr) > 1:
        rep = " ".join(repr)
    if rep:
        alert.append(rep)
        guide_6_one(replies)
    elif pl:
        gmc[6] = command.payload
        guide_7(command, replies)
    else:
        alert.append("⚠️ expects argument")
        guide_6_one(replies)


def guide_6_both(replies):
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = f"For protocol {gmc[5]} you may choose a port.\n(Default: any)\n\nAllowed values for *port*:\n・ a single port (e.g 80)"
    dbot.commands.register(name="/b", func=guide_5)
    dbot.commands.register(name="//", func=guide_6_both_pl)
    s = ""
    d = ""
    if not any(c in gmc[6] for c in (",", ":")):
        dbot.commands.register(name="/s", func=guide_7)
        s = "\n🔺 /s  (skip)"
    if gmc[6] != gmd[6]:
        dbot.commands.register(name="/d", func=guide_6_both_def)
        d = "\n🔺 /d  (default)"
    replies.add(
        f"{alrt}🌐 GUIDE (7/8)\n{txt}\n\n{guide_r(6)}\n\n🔺 //  *port*{d}\n🔺 /b  (back){s}\n🔺 /q  (quit)"
    )


def guide_6_both_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[6] = gmd[6]
    guide_7(command, replies)


def guide_6_both_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    pl = [c for c in re.split(",|:", command.payload) if c.strip()]
    if len(pl) != 1:
        alert.append("⚠️ expects one argument")
    elif not pl[0].isnumeric():
        alert.append("⚠️ argument must be numeric")
    elif int(pl[0]) <= 0 or int(pl[0]) > 65535:
        alert.append("⚠️ argument must be valid portnumber")
    else:
        gmc[6] = pl[0]
        guide_7(command, replies)
        return
    guide_6_both(replies)


def guide_6_other(replies):
    txt = f"No port specification is allowed for protocol {gmc[5]}!"
    dbot.commands.register(name="/b", func=guide_5)
    s = ""
    d = ""
    if gmc[6] == gmd[6]:
        dbot.commands.register(name="/s", func=guide_7)
        s = "\n🔺 /s  (skip)"
    else:
        dbot.commands.register(name="/d", func=guide_6_other_def)
        d = "\n🔺 /d  (default)"
        txt = f"{txt}\n\nPlease use  /d  to set ports to default (any) or  /b  to go back and choose a different protocol"
    replies.add(
        f"🌐 GUIDE (7/8)\n{txt}\n\n{guide_r(6)}\n{d}\n🔺 /b  (back){s}\n🔺 /q  (quit)"
    )


def guide_6_other_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[6] = gmd[6]
    guide_7(command, replies)


def guide_7(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    txt = "Would you like to add a comment to this rule?\nThis setting is optional (Default: None)\n\nYou may specify a comment using  // whateveryoulikeincludingspacesandsuch"
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_6)
    dbot.commands.register(name="/s", func=guide_finish)
    dbot.commands.register(name="//", func=guide_7_pl)
    d = ""
    if gmc[7] != gmd[7]:
        dbot.commands.register(name="/d", func=guide_7_def)
        d = "\n🔺 /d  (default)"
    replies.add(
        f"{alrt}🌐 GUIDE (8/8)\n{txt}\n\n{guide_r(7)}\n\n🔺 //  *comment*{d}\n🔺 /b  (back)\n🔺 /s  (skip)\n🔺 /q  (quit)"
    )


def guide_7_def(command, replies):
    """."""
    if not verify(command.message):
        return
    gmc[7] = gmd[7]
    guide_finish(command, replies)


def guide_7_pl(command, replies):
    """."""
    if not verify(command.message):
        return
    if not command.payload:
        alert.append("⚠️ expects comment")
        guide_7(command, replies)
    else:
        gmc[7] = command.payload
        guide_finish(command, replies)


def guide_finish(command, replies):
    """."""
    if not verify(command.message):
        return
    alrt = ""
    if alert:
        alrt = f"{alert[0]}\n\n"
        alert.clear()
    x = "add"
    if gmc[0] != gmd[0]:
        x = "insert"
    txt = f"Rule building is done.\nPlease check if the rule below matches your expectation, if so you may use  /f  to {x} this rule and finish this guide."
    guide_unreg()
    dbot.commands.register(name="/b", func=guide_6)
    dbot.commands.register(name="/f", func=guide_exec)
    replies.add(
        f"{alrt}🌐 GUIDE\n{txt}\n\n{guide_r(8)}\n\n🔺 /f  (finish)\n🔺 /b  (back)\n🔺 /q  (quit)"
    )


def guide_exec(command, replies):
    """."""
    if not verify(command.message):
        return
    clear_cmd()
    p = ufwp.UFWParser()
    for c in ["b", "f", "q"]:
        with suppress(Exception):
            dbot.commands.unregister(name=f"/{c}")
    x = []
    if gmc[0] != gmd[0]:
        x.append("insert")
        x.append(gmc[0])
        p.register_command(ufwp.UFWCommandRule("insert"))
    x.append(gmc[2])
    if gmc[1] != gmd[1]:
        x.append("out")
    x.append("from")
    if gmc[3] != gmd[3]:
        x.append(gmc[3])
    else:
        x.append(gmd[3])
    x.append("to")
    if gmc[4] != gmd[4]:
        x.append(gmc[4])
    else:
        x.append(gmd[4])
    if gmc[5] != gmd[5]:
        x.append("proto")
        x.append(gmc[5])
    if gmc[6] != gmd[6]:
        x.append("port")
        x.append(gmc[6])
    if gmc[7] != gmd[7]:
        x.append("comment")
        x.append(gmc[7])
    p.register_command(ufwp.UFWCommandRule(gmc[2]))
    try:
        pr = p.parse_command(x)
        fw()[0].do_action(
            pr.action,
            pr.data.get("rule", ""),
            pr.data.get("iptype", ""),
            True,
        )
    except Exception as xcp:
        alert.append(f"⛔️ ufw exception: {xcp}")
        guide_finish(command, replies)
        return
    except:
        alert.append(f"📛 ufw error")
        guide_finish(command, replies)
        return
    x = []
    for c in fw()[1].get_rules():
        x.append(f"🔹 {len(x) + 1}:  {ufwp.UFWCommandRule.get_command(c)}")
    x = "\n".join(x)
    replies.add(f"🌐 RULES\n{x}")
    gmc.clear()
    menu()


# >>> SCAN


def scan(command, replies):
    """."""
    if not verify(command.message):
        return
    replies.add(
        f"🌐 SCAN\nPlease check\nhttps://github.com/janekc/firewall-bot for version greater than {version}"
    )


# >>> TESTCODE / NOTES

# NOPE: support for named protocols -> rules will use the actual ports, user might not recognize
# NOPE: mark added/modified/inserted rule -> can't account for rule already existing and/or parsing/format changes
# NOPE: f-string alignment -> no monospaced font in chats
# NOPE: find better ufw man and set link -> no better manpage available

# TODO: scan
# TODO: add ufw and python version to /info, add nmap info (installed, version)
# TODO: code optimization for service_set(), service() and others
# TODO: comments / docstrings
