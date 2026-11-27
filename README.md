# Tunnelcheck / HTTPCheck

مجموعة أدوات صغيرة بلغة Go لفهم إعدادات HTTP/1.1 وHTTP/2 على موقع مصرح باختباره، وللتحقق المنفصل من طلبات HTTP CONNECT إلى بروكسي تملكه.

> لا تفحص إلا الأنظمة التي تملكها أو لديك إذن صريح لاختبارها. وضع `-authorized` إقرار نطاق محلي ولا يمنح إذنًا قانونيًا.

## فحص موقعك من دون مختبر أو Docker

يتطلب Go 1.26 أو أحدث. استنسخ المستودع وشغّل الاختبارات وثبّت الأمرين:

```bash
git clone https://github.com/l7b7/tunnelcheck.git
cd tunnelcheck
go test ./...
go install ./cmd/httpcheck ./cmd/tunnelcheck
```

تأكد أن `$(go env GOPATH)/bin` ضمن `PATH`، ثم افحص عنوانًا تملكه:

```bash
httpcheck scan -url https://your-site.example -authorized
```

أو أخرج تقرير JSON:

```bash
httpcheck scan -url https://your-site.example -authorized -json
```

يُرسل الفحص طلب `HEAD` واحدًا عبر HTTP/1.1 وطلبًا واحدًا عبر HTTP/2 إلى TLS HTTPS. لا يتبع التحويلات، ويحذف query string من العنوان، ولا يجرب حمولة هجومية. يعرض نسخة HTTP التي رد بها الخادم، وحالة الاستجابة، وALPN، والمدة، ومجموعة محدودة من الترويسات.

المخرجات الافتراضية ملخص مقروء: استجابة البروتوكولات، الترويسات المشاهدة، وملاحظات مراجعة غير مصنفة كثغرات. استخدم `-json` عندما تريد إدخال النتائج في سكربت أو أداة أخرى.

هذا **فحص وضع بروتوكول ومؤشرات استجابة**، وليس اختبار استغلال. النتيجة لا تثبت وجود ثغرة HTTP/2 أو HTTP/1.1؛ فذلك يتطلب مراجعة مكونات المسار الوسيطة واختبارات متخصصة مصرح بها.

إذا أدخلت عنوانًا من نوع HTTP غير المشفر، يفحص HTTP/1.1 فقط؛ لا يحاول HTTP/2 cleartext (h2c). فشل HEAD أو رفضه يعني أن الفحص لم يحصل على استجابة ناجحة بذلك البروتوكول، ولا يثبت وحده أن الخادم لا يدعمه.

## البحث عن CVE

أدخل معرّف CVE لجلب الملخص، وحالة السجل، وCVSS/CWE والمراجع المنشورة في NVD:

```bash
httpcheck cve -id CVE-2023-44487
httpcheck cve -id CVE-2023-44487 -json
```

يتطلب ذلك اتصالًا بالإنترنت. استعلام CVE يرسل المعرّف إلى واجهة NVD العامة. بيانات CVE تشرح الثغرة ولا تحدد وحدها هل موقع بعينه متأثر.

## فحص HTTP CONNECT عبر بروكسي تملكه

هذه وظيفة منفصلة عن فحص الموقع. تحتاج عنوان بروكسي فعليًا؛ لا تضع عنوان الموقع في `-proxy`:

```bash
tunnelcheck -proxy http://proxy.example:8080 \
  -target your-site.example:443 \
  -authorized-target your-site.example:443 \
  -protocol h1 -json
```

HTTP/2 CONNECT يحتاج بروكسي TLS يتفاوض على ALPN `h2`:

```bash
tunnelcheck -proxy https://proxy.example:9443 \
  -target your-site.example:443 \
  -authorized-target your-site.example:443 \
  -protocol h2 -json
```

Tunnelcheck ترسل طلب CONNECT واحدًا، ولا تمرر أو ترسل حمولة داخل النفق. قبول البروكسي لا يثبت وحده أثرًا أمنيًا.

## المختبر الاختياري

Docker Compose وOpenSSL مطلوبان فقط للمختبر المحلي، وليسا مطلوبين لفحص موقعك أو البحث عن CVE. إذا لم يتوفر Docker، تخط هذا القسم.

```bash
bash labs/make-certs.sh
docker compose -f labs/docker-compose.yml up --build
```

راجع [دليل المختبر](labs/README.md) لتشغيل بروكسي Envoy المقيد محليًا. لإيقافه استخدم `docker compose -f labs/docker-compose.yml down`.

## التطوير والإصدارات

```bash
gofmt -w cmd
go test ./...
go vet ./...
```

يُشغل CI الاختبارات ويفحص البناء. عند إنشاء وسم إصدار `v*`، يبني GitHub Actions برنامجي `httpcheck` و`tunnelcheck` لـLinux amd64 وarm64 ويرفق بصمات SHA-256.

## المراجع

- [RFC 9110 — HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [RFC 9113 — HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113)
- [NVD Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities)
- [بحث HTTP/2 CONNECT](https://blog.flomb.net/posts/http2connect/)

## الترخيص

MIT. راجع [LICENSE](LICENSE).

