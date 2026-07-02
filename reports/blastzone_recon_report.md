# 🔴 红队评估报告 - blastzone-站群资产侦察

| 项目 | blastzone-站群资产侦察 |
|------|-------------|
| 目标 | blastzone.org |
| 日期 | 2026-06-24 01:56:41 |

---

## 资产概览

```json
{
  "关联域名": [
    "blastzone.org",
    "blastzone.com",
    "blastzonewebhosting.com",
    "lokiresearch.com",
    "artfulbullet.com"
  ],
  "服务器数量": "17+",
  "子域名数量": "50+",
  "IP段": "216.215.30.32/28 + 66.113.102.192/27 + 173.209.174.233",
  "ISP": "Grant County PUD (AS19800) + opticfusion.net (AS30170) + Ziply Fiber (AS13370)"
}
```

## 站群关联证据链

| 严重度 | 类型 | 目标 | 证据 |
|--------|------|------|------|
| - | - | - | NS 交叉: blastzone.org + lokiresearch.com 的 NS 都指向 ns1/ns2.blastzonewebhosting.com |
| - | - | - | MX 交叉: blastzonewebhosting.com 的 MX 指向 mail.blastzone.org |
| - | - | - | SPF 同段: 三个域名 SPF 都授权 ip4:216.215.30.32/28 + ip4:66.113.102.192/27 |
| - | - | - | 历史 IP 重叠: artfulbullet.com 历史 IP (.38/.200/.196) 全部在站群段内 |
| - | - | - | DKIM 同账号: 4 个域名共用 DKIM selector em1093523 |
| - | - | - | 旁站发现: lokiresearch.com 与 bzwin1.blastzone.org 共享 216.215.30.34 |

## 完整 IP 资产清单

| 严重度 | 类型 | 目标 | 证据 |
|--------|------|------|------|
| **critical** | Proxmox VE | `216.215.30.35` | proxmox.blastzone.org 虚拟化管理 — 控制全部 VM |
| **critical** | phpMyAdmin | `216.215.30.37` | bzhost1 phpMyAdmin — 数据库管理 |
| **critical** | RDP 开放 | `173.209.174.233:3389` | home.blastzone.org RDP 暴露公网 |
| **critical** | Blue Iris | `173.209.174.233:81` | 安防摄像头管理系统 |
| **high** | Webmail | `216.215.30.37` | webmail.blastzone.org |
| **high** | Webmail | `66.113.102.196` | webmail.blastzonewebhosting.com |
| **high** | 最忙服务器 | `66.113.102.213` | bzweb3/4 + kb + rasaero + rt |
| **medium** | IIS | `216.215.30.34` | bzwin1 + www + lokiresearch.com |
| **medium** | 邮件 | `216.215.30.36` | mail/mailout/mx.blastzone.org |
| **medium** | 宿主机 | `216.215.30.38` | bzhost2 + artfulbullet(历史) |
| **medium** | Mailman | `216.215.30.39` | mailman.blastzone.org |
| **medium** | Web LB | `66.113.102.199` | bzwebl2 |
| **medium** | Web LB | `66.113.102.200` | bzwebl5 + artfulbullet(历史) |
| **medium** | Web LB | `66.113.102.201` | bzwebl4 + myth-racing |
| **medium** | Wiki | `66.113.102.205` | bzwiki.blastzone.org |
| **medium** | Web | `66.113.102.216` | bzweb5.blastzone.org |
| **medium** | 邮件 | `66.113.102.222` | mail/smtp/imap.lokiresearch.com |
| **low** | MX | `66.113.102.195` | mx1.blastzone.org |
| **low** | MX | `66.113.102.198` | mx1.blastzone.com |
| **low** | MX | `66.113.102.215` | mx.blastzone.org |
| **low** | VC | `66.113.102.194` | vc.blastzonewebhosting.com |
| **low** | 未知 | `66.113.102.202` | ktl1.blastzone.org |

## 侦察方法

```json
{
  "数据源": "Shodan + Censys + VirusTotal + SecurityTrails + OTX + MyIP.ms + crt.sh + HackerTarget",
  "工具": "AI-Burp V4 (IntelAggregator + AssetExpander + CDNBypass)",
  "轮次": "三轮扩散: 域名->IP->旁站->C段->历史DNS->反向DNS->ASN",
  "API KEY": "5 个平台全部已配置"
}
```

---
*AI-Burp V4 自动生成 | 2026-06-24 01:56:41*
*本报告仅供授权方使用，未经许可不得传播*