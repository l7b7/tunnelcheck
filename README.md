# Tunnelcheck

أداة CLI بلغة Go لفحص استجابة بروكسي HTTP لطلب CONNECT واحد عبر HTTP/1.1 أو HTTP/2. تفحص قبول البروكسي أو رفضه لوجهة واحدة تحددها، من دون إرسال حمولة داخل النفق.

> استخدمها فقط على بروكسي ووجهة تملكهما أو لديك إذن صريح لاختبارهما.

## المزايا

- HTTP/1.1 CONNECT بنمط نصي، وHTTP/2 CONNECT عبر TLS وALPN `h2`.
- تحقق شهادة TLS مفعّل دائمًا؛ يمكن إضافة CA مختبر عبر `-ca-file`.
- تأكيد نطاق لكل تشغيل: `-authorized-target` يجب أن يطابق `-target`.
- مخرجات نصية أو JSON، ومهلة اتصال محدودة.
- لا بيانات اعتماد في عنوان البروكسي، ولا تمرير أو إرسال لحمولة النفق.
- مختبر Envoy محلي محدود إلى loopback ووجهة اختبار ثابتة.
- اختبارات بروتوكول، وCI، وإصدارات Linux amd64 وarm64.

## المتطلبات

Go 1.26 أو أحدث. لتشغيل المختبر: Docker Compose وOpenSSL.

## التثبيت على Kali Linux

```bash
git clone https://github.com/l7b7/tunnelcheck.git
cd tunnelcheck
go test ./...
go install ./cmd/tunnelcheck
```

أو استخدم `bash scripts/install-kali.sh`. تأكد أن `$(go env GOPATH)/bin` ضمن `PATH`.

## تشغيل محلي

أنشئ شهادة المختبر وشغّل Envoy والهدف المحلي:

```bash
bash labs/make-certs.sh
docker compose -f labs/docker-compose.yml up --build
```

فحص HTTP/1.1:

```bash
tunnelcheck -proxy http://127.0.0.1:8080 -target 127.0.0.1:8443 -authorized-target 127.0.0.1:8443 -protocol h1 -json
```

فحص HTTP/2:

```bash
tunnelcheck -proxy https://127.0.0.1:9443 -ca-file labs/certs/proxy.crt -target 127.0.0.1:8443 -authorized-target 127.0.0.1:8443 -protocol h2 -json
```

أوقف المختبر بعد الانتهاء:

```bash
docker compose -f labs/docker-compose.yml down
```

راجع [دليل المختبر](labs/README.md) للمراحل التعليمية الخمس، وشرح الإطارات، والاختبارات المحلية.

## تفسير النتيجة

- `tunnel_accepted`: رد البروكسي بحالة 2xx. هذا لا يثبت وحده وجود خدمة خلف الوجهة أو أثر أمني.
- `tunnel_rejected`: البروكسي رفض الطلب أو أغلق stream.
- `error`: تعذر الاتصال أو تفاوض TLS/HTTP/2 أو انتهت المهلة.

اربط النتيجة بسياسة البروكسي وسجلاته وخدمة اختبار معروفة داخل النطاق المصرح.

## حدود الأداة

وجهة واحدة في كل تشغيل. لا قوائم أهداف أو CIDR أو اكتشاف مضيفين. لا تمرير TCP عام ولا قراءة أو كتابة لحمولة النفق. لا تعطيل للتحقق من الشهادات، ولا دعم لمصادقة البروكسي في هذا الإصدار. رموز الخروج: 0 قبول، 1 رفض، 2 خطأ إعداد أو اتصال.

## التطوير

```bash
gofmt -w cmd/tunnelcheck labs/target
go test ./...
go vet ./...
go build -trimpath ./cmd/tunnelcheck
```

## المراجع

- [RFC 9110 — HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [RFC 9113 — HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113)
- [بحث HTTP/2 CONNECT](https://blog.flomb.net/posts/http2connect/)

## الترخيص

MIT. راجع [LICENSE](LICENSE).
