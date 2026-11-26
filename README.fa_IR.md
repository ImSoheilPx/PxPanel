<p align="center">
  <img src="media/logo.png" alt="لوگوی PxPanel" width="160" />
</p>

<h1 align="center">PxPanel</h1>

<p align="center">
  پنل مدیریت همه‌کارهٔ Xray — تقویت‌شده، توسعه‌یافته و چندپروتکلی.
</p>

<p align="center">
  <a href="https://github.com/ImSoheilPx/pxpanel/releases/latest"><img src="https://img.shields.io/github/v/release/ImSoheilPx/pxpanel?style=flat-square" alt="آخرین نسخه" /></a>
  <a href="https://github.com/ImSoheilPx/pxpanel/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ImSoheilPx/pxpanel?style=flat-square" alt="مجوز: GPL-3.0" /></a>
  <a href="https://github.com/ImSoheilPx/pxpanel/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ImSoheilPx/pxpanel/ci.yml?branch=main&style=flat-square" alt="CI" /></a>
</p>

[English](/README.md) | [فارسی](/README.fa_IR.md)

---

## دربارهٔ PxPanel

PxPanel یک پنل وب متن‌باز و همه‌کاره برای مدیریت سرورهای
[Xray-core](https://github.com/XTLS/Xray-core) است. این پنل رابط کاربری تمیز و
چندزبانه‌ای برای استقرار، پیکربندی و پایش طیف گسترده‌ای از پروتکل‌های پروکسی و
VPN فراهم می‌کند — از یک سرور مجازی تا استقرارهای چندگرهی — و با افزودن مجموعهٔ
بزرگی از پروتکل‌های VPN و قابلیت‌های مدیریتی، فراتر از هستهٔ Xray پیش می‌رود.

> [!IMPORTANT]
> این پروژه صرفاً برای استفادهٔ شخصی است. لطفاً از آن برای مقاصد غیرقانونی یا در
> محیط عملیاتی (Production) استفاده نکنید.

## قابلیت‌ها

### هستهٔ پنل

- **اینباندهای چندپروتکلی Xray** — VLESS، VMess، Trojan، Shadowsocks، WireGuard،
  AmneziaWG، TUIC v5، Hysteria2، MTProto، HTTP، SOCKS (Mixed)، Dokodemo-door /
  Tunnel و TUN.
- **ترنسپورت‌ها و امنیت مدرن** — TCP (Raw)، mKCP، WebSocket، gRPC، HTTPUpgrade و
  XHTTP با امنیت TLS، XTLS و REALITY.
- **AmneziaWG داخلی** — WireGuard مقاوم در برابر DPI به‌صورت userspace داخل خود
  پنل اجرا می‌شود؛ بدون ماژول کرنل، DKMS یا بسته‌های اضافی.
- **مدیریت به تفکیک کاربر** — سهمیهٔ ترافیک، تاریخ انقضا، محدودیت IP با
  آدرس‌های مورد اطمینان، محدودیت دستگاه (HWID)، چرخهٔ تمدید زمان‌بندی‌شده، وضعیت
  آنلاین زنده، لینک اشتراک یک‌کلیکی، QR Code و اشتراک.
- **آمار ترافیک** — به تفکیک اینباند، کاربر و اوت‌باند، همراه با کنترل ریست و
  تاریخچهٔ مصرف.
- **پشتیبانی از چند نود (Multi-Node)** — مدیریت و مقیاس‌دهی چند سرور از یک پنل
  اصلی، شامل کلون‌کردن اینباندها روی نودهای دیگر.
- **اوت‌باند و مسیریابی** — WARP، قوانین مسیریابی سفارشی، بالانسرها و زنجیرهٔ
  پروکسی اوت‌باند.
- **سرور اشتراک داخلی** — خروجی Raw، JSON و Clash که به‌صورت خودکار بر اساس
  User-Agent کلاینت انتخاب می‌شود.
- **API رست‌کرده** با توکن‌های محدودشده و اختیاری-انقضادار به همراه مرجع API داخل
  پنل.
- **دسترسی امن** — ورود دومرحله‌ای (TOTP)، یکپارچگی با Fail2ban برای اعمال
  محدودیت IP، نشست‌های محافظت‌شده با CSRF.
- **مدیریت گواهی SSL** — صدور و تمدید خودکار گواهی با acme.sh.
- **بات‌های اطلاع‌رسانی** — تلگرام، Discord و WeChat برای رویدادهای ترافیک،
  انقضا و بکاپ.
- **ذخیره‌سازی منعطف** — SQLite (پیش‌فرض) یا PostgreSQL.
- **نصب‌شدنی به‌صورت PWA** — PxPanel را روی صفحهٔ اصلی گوشی یا دسکتاپ پین کنید.
- **۱۴ زبان رابط کاربری** با تم تیره و روشن.

### پروتکل‌های توسعه‌یافته و قابلیت‌های مدیریتی

- پروتکل‌های VPN: **PPTP، L2TP RAW، L2TP/IPsec، OpenVPN، OpenConnect، SSTP،
  IKEv2، WireGuard C، AmneziaWG، GRE، MTProto، SSH**
- سیستم **نمایندگی (Reseller)**
- پشتیبانی **چند ادمین (Multi-Admin)**
- مدیریت **تنظیمات هسته (Core Settings)**

## شروع سریع

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ImSoheilPx/pxpanel/main/install.sh)
```

برای نصب نسخهٔ مشخص، تگ آن را در انتهای دستور بنویسید (مثلاً `v1.0.0`):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ImSoheilPx/pxpanel/main/install.sh) v1.0.0
```

در زمان نصب، نام کاربری، رمز عبور و مسیر دسترسی تصادفی تولید می‌شود. پس از نصب،
دستور `pxpanel` را اجرا کنید تا منوی مدیریت باز شود؛ از آنجا می‌توانید سرویس را
استارت/استاپ کنید، اطلاعات ورود را مشاهده یا ریست کنید و گواهی SSL مدیریت کنید.

نصب‌کننده این موارد را برپا می‌کند:

- سرویس `pxpanel` در systemd (و OpenRC روی Alpine) — پیکربندی در `/etc/pxpanel`،
  باینری‌ها در `/usr/local/pxpanel` و لاگ‌ها در `/var/log/pxpanel`
- ابزار خط فرمان `pxpanel` در مسیر `/usr/bin/pxpanel`

هر فایل انتشار همراه با فایل `.sha256` منتشر می‌شود و `install.sh` و به‌روزرسان
پنل پیش از نصب صحت آرشیو را با این جمع کنترلی می‌سنجند.

### داکر

```bash
docker compose up -d
```

ایمج در `ghcr.io/ImSoheilPx/pxpanel` منتشر می‌شود. Fail2ban همراه ایمج، محدودیت
IP کاربران را با `iptables` اعمال می‌کند که به قابلیت `NET_ADMIN` نیاز دارد —
`docker-compose.yml` این قابلیت را از قبل با `cap_add` تنظیم کرده است:

```bash
docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW ... ghcr.io/ImSoheilPx/pxpanel
```

## سیستم‌عامل‌های تست‌شده

| سیستم‌عامل | وضعیت |
|---|---|
| Ubuntu 22.04 / 24.04 | ✅ تست شده |
| Ubuntu 20.04 | ✅ تست شده |
| Debian 11 / 12 | ✅ تست شده |
| CentOS Stream 9+ | ✅ تست شده |
| AlmaLinux 9 / Rocky Linux 9 | ✅ تست شده |
| Fedora 38+ | ✅ تست شده |
| Arch Linux | ✅ تست شده |
| openSUSE Tumbleweed | ✅ تست شده |
| Alpine Linux | ✅ تست شده (Docker) |

**معماری‌ها:** `amd64` · `386` · `arm64` (aarch64) · `armv7` · `armv6` ·
`armv5` · `s390x`.

## اسکرین‌شات‌ها

اسکرین‌شات‌ها به‌زودی اضافه می‌شوند.

## گزینه‌های پایگاه داده

PxPanel از دو بک‌اند پشتیبانی می‌کند که در زمان نصب انتخاب می‌شوند:

- **SQLite** (پیش‌فرض) — یک فایل واحد در مسیر `/etc/pxpanel/pxpanel.db`؛ بدون
  نیاز به راه‌اندازی، مناسب استقرارهای کوچک و متوسط.
- **PostgreSQL** — برای تعداد بالای کاربر یا استقرارهای چندگرهی توصیه می‌شود.

در زمان اجرا، بک‌اند با متغیرهای محیطی انتخاب می‌شود (نصب‌کننده آن‌ها را در
`/etc/default/pxpanel` می‌نویسد):

```
PXPANEL_DB_TYPE=postgres
PXPANEL_DB_DSN=postgres://pxpanel:***@127.0.0.1:5432/pxpanel?sslmode=disable
```

## قدردانی

پروژه PxPanel فورکی از [3x-ui](https://github.com/MHSanaei/3x-ui) است که تقویت
شده و قابلیت‌های بسیاری به آن اضافه شده است. اعتبار پنل اصلی متعلق به
مشارکت‌کنندگان 3x-ui است؛ این مخزن همان کار را زیر همان مجوز GPL-3.0 ادامه می‌دهد.

## مشارکت

از مشارکت‌ها استقبال می‌کنیم. پیش از ثبت ایشو یا پول‌ریکوئست،
[راهنمای مشارکت](/CONTRIBUTING.md) را مطالعه کنید.

## مجوز

PxPanel تحت مجوز [GPL-3.0](LICENSE) منتشر شده است.
