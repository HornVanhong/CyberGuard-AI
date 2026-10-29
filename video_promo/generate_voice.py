import asyncio
import os
import edge_tts

VOICE = "km-KH-PisethNeural"

SCENES = [
    {
        "id": "scene1",
        "name": "Scene 1: The Hook (0s-4s)",
        "text": "រាល់ថ្ងៃ ឯកសារបង្កប់មេរោគរាប់ពាន់កំពុងវាយលុកក្នុង Telegram! កុំទាន់បើក បើមិនទាន់បានស្កេន!",
        "rate": "+15%",
        "pitch": "+0Hz",
        "output": "vo_scene1.mp3",
    },
    {
        "id": "scene2",
        "name": "Scene 2: Reveal (4s-8s)",
        "text": "សូមណែនាំ CyberGuard AI. ជំនួយការការពារសុវត្ថិភាពឌីជីថល ២៤ ម៉ោងលើ Telegram!",
        "rate": "+10%",
        "pitch": "+0Hz",
        "output": "vo_scene2.mp3",
    },
    {
        "id": "scene3",
        "name": "Scene 3: Real Demo (8s-17s)",
        "text": "គ្រាន់តែ Forward ឯកសារគួរឱ្យសង្ស័យចូលមក! ប្រព័ន្ធនឹងវិភាគភ្លាមៗជាមួយ ClamAV, YARA និង Google Gemini AI ដើម្បីពន្យល់ពីហានិភ័យយ៉ាងលម្អិត!",
        "rate": "+15%",
        "pitch": "+0Hz",
        "output": "vo_scene3.mp3",
    },
    {
        "id": "scene4",
        "name": "Scene 4: Engines (17s-23s)",
        "text": "ដំណើរការដោយម៉ាស៊ីនស្កេនកម្រិតខ្ពស់ចំនួន ១២, ព្រមទាំងប្រព័ន្ធ Decompile កូដ Ghidra ដោយស្វ័យប្រវត្តិ!",
        "rate": "+12%",
        "pitch": "+0Hz",
        "output": "vo_scene4.mp3",
    },
    {
        "id": "scene5",
        "name": "Scene 5: Call to Action (23s-30s)",
        "text": "ការពារទិន្នន័យរបស់អ្នកឥឡូវនេះ! ចូល Telegram រួចស្វែងរក SmartPTbot, ប្រើប្រាស់ឥតគិតថ្លៃ ១០០%!",
        "rate": "+12%",
        "pitch": "+0Hz",
        "output": "vo_scene5.mp3",
    },
]

async def main():
    out_dir = os.path.join(os.path.dirname(__file__), "public", "audio")
    os.makedirs(out_dir, exist_ok=True)
    
    for s in SCENES:
        filepath = os.path.join(out_dir, s["output"])
        communicate = edge_tts.Communicate(s["text"], VOICE, rate=s["rate"], pitch=s["pitch"])
        await communicate.save(filepath)
        size = os.path.getsize(filepath)
        print(f"[{s['id']}] Generated {s['output']} ({size} bytes)")

    # Also generate full track
    full_text = (
        "រាល់ថ្ងៃ ឯកសារបង្កប់មេរោគរាប់ពាន់កំពុងវាយលុកក្នុង Telegram! កុំទាន់បើក បើមិនទាន់បានស្កេន! "
        "សូមណែនាំ CyberGuard AI. ជំនួយការការពារសុវត្ថិភាពឌីជីថល ២៤ ម៉ោងលើ Telegram! "
        "គ្រាន់តែ Forward ឯកសារគួរឱ្យសង្ស័យចូលមក! ប្រព័ន្ធនឹងវិភាគភ្លាមៗជាមួយ ClamAV, YARA និង Google Gemini AI ដើម្បីពន្យល់ពីហានិភ័យយ៉ាងលម្អិត! "
        "ដំណើរការដោយម៉ាស៊ីនស្កេនកម្រិតខ្ពស់ចំនួន ១២, ព្រមទាំងប្រព័ន្ធ Decompile កូដ Ghidra ដោយស្វ័យប្រវត្តិ! "
        "ការពារទិន្នន័យរបស់អ្នកឥឡូវនេះ! ចូល Telegram រួចស្វែងរក SmartPTbot, ប្រើប្រាស់ឥតគិតថ្លៃ ១០០%!"
    )
    full_path = os.path.join(out_dir, "voiceover-khmer.mp3")
    comm_full = edge_tts.Communicate(full_text, VOICE, rate="+14%", pitch="+0Hz")
    await comm_full.save(full_path)
    print(f"[full] Generated full voiceover-khmer.mp3 ({os.path.getsize(full_path)} bytes)")

if __name__ == "__main__":
    asyncio.run(main())
