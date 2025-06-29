# Repomix में योगदान

Repomix एक ओपन सोर्स प्रोजेक्ट है और हम योगदान का स्वागत करते हैं! यह गाइड आपको Repomix के विकास में शामिल होने के लिए आवश्यक जानकारी प्रदान करेगी।

## विकास परिवेश सेटअप

### आवश्यकताएँ

- Node.js (v20 या उच्चतर)
- npm, yarn, या pnpm
- Git

### रिपॉजिटरी क्लोन करना

```bash
git clone https://github.com/yamadashy/repomix.git
cd repomix
```

### निर्भरताएँ इंस्टॉल करना

```bash
# npm का उपयोग करके
npm install

# या yarn का उपयोग करके
yarn

# या pnpm का उपयोग करके
pnpm install
```

### विकास सर्वर चलाना

```bash
# npm का उपयोग करके
npm run dev

# या yarn का उपयोग करके
yarn dev

# या pnpm का उपयोग करके
pnpm dev
```

## प्रोजेक्ट संरचना

Repomix प्रोजेक्ट निम्नलिखित प्रमुख डायरेक्टरी में संगठित है:

- `src/`: मुख्य सोर्स कोड
  - `cli/`: कमांड लाइन इंटरफेस कोड
  - `core/`: कोर फंक्शनैलिटी
  - `utils/`: उपयोगिता फंक्शन
- `test/`: टेस्ट फाइलें
- `website/`: दस्तावेज़ीकरण वेबसाइट
- `scripts/`: बिल्ड और विकास स्क्रिप्ट

## टेस्टिंग

Repomix में व्यापक टेस्ट सूट है। टेस्ट चलाने के लिए:

```bash
# सभी टेस्ट चलाएँ
npm test

# या विशिष्ट टेस्ट चलाएँ
npm test -- -g "specific test name"
```

## बिल्डिंग

प्रोडक्शन बिल्ड बनाने के लिए:

```bash
npm run build
```

बिल्ड आउटपुट `dist/` डायरेक्टरी में जनरेट होगा।

## लिंटिंग और फॉर्मेटिंग

Repomix ESLint और Prettier का उपयोग करता है। कोड लिंट करने के लिए:

```bash
npm run lint
```

कोड फॉर्मेट करने के लिए:

```bash
npm run format
```

## पुल रिक्वेस्ट प्रक्रिया

1. अपना फीचर ब्रांच बनाएँ (`git checkout -b feature/amazing-feature`)
2. अपने परिवर्तन कमिट करें (`git commit -m 'Add amazing feature'`)
3. अपना ब्रांच पुश करें (`git push origin feature/amazing-feature`)
4. GitHub पर एक पुल रिक्वेस्ट खोलें

## रिलीज प्रक्रिया

Repomix सेमांटिक वर्जनिंग का पालन करता है। रिलीज प्रक्रिया स्वचालित है और GitHub Actions के माध्यम से संचालित होती है।

## दस्तावेज़ीकरण

दस्तावेज़ीकरण वेबसाइट VitePress का उपयोग करती है और `website/` डायरेक्टरी में स्थित है। दस्तावेज़ीकरण विकास सर्वर चलाने के लिए:

```bash
cd website
npm install
npm run dev
```

## अगला क्या है?

- [Repomix को लाइब्रेरी के रूप में उपयोग](using-repomix-as-a-library.md) के बारे में जानें
- [AI-सहायक विकास टिप्स](../tips/best-practices.md) का अन्वेषण करें
