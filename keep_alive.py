from flask import Flask, render_template_string
from threading import Thread
import time

app = Flask(__name__)

# تصميم الصفحة (HTML + CSS) مدمج داخل الكود
PAGE_DESIGN = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>حالة البوت | Bot Status</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&display=swap');

        body {
            font-family: 'Cairo', sans-serif;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff;
            margin: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            overflow: hidden;
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            padding: 2rem;
            border-radius: 20px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
            animation: fadeIn 1s ease-out;
        }

        .status-container {
            margin-bottom: 20px;
        }

        .status-dot {
            height: 25px;
            width: 25px;
            background-color: #00ff88;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.7);
            animation: pulse 2s infinite;
            vertical-align: middle;
            margin-left: 10px;
        }

        h1 { margin: 0; font-size: 1.5rem; color: #fff; }
        p { color: #aeb2b8; font-size: 0.9rem; margin-top: 10px; }

        .info-box {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            text-align: right;
        }

        .info-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding-bottom: 5px;
        }
        .info-item:last-child { border-bottom: none; margin-bottom: 0; }

        .label { color: #00d2ff; font-weight: bold; }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 136, 0); }
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>
    <div class="card">
        <div class="status-container">
            <span class="status-dot"></span>
            <span style="font-size: 1.2rem; font-weight: bold;">النظام يعمل بكفاءة</span>
        </div>
        <h1>بوت الإعلانات الدراسية</h1>
        <p>يتم مراقبة هذا البوت لضمان بقائه متصلاً 24/7</p>

        <div class="info-box">
            <div class="info-item">
                <span class="value">Python / Telegram API</span>
                <span class="label">التقنية</span>
            </div>
            <div class="info-item">
                <span class="value">بوعناني عبد القادر</span>
                <span class="label">المطور</span>
            </div>
            <div class="info-item">
                <span class="value">نشط ✅</span>
                <span class="label">الحالة</span>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(PAGE_DESIGN)

def run():
    print("-" * 50)
    print("🌐 خادم الويب قيد التشغيل الآن.")
    print("🔗 الرابط هو عنوان مشروعك الظاهر في نافذة 'WebView'.") 
    print("-" * 50)
    # إعدادات المضيف والمنفذ
    app.run(host="0.0.0.0", port=8080)

def keep_alive():
    t = Thread(target=run)
    t.start()
