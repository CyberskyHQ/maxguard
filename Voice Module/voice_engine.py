import os
import speech_recognition as sr
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def listen_for_command():
    """Captures voice input from the mic."""
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        recognizer.adjust_for_ambient_noise(source, duration=1)
        try:
            audio = recognizer.listen(source, timeout=5)
            text = recognizer.recognize_google(audio).lower()
            return text
        except:
            return None

def get_voice_response(text):
    """Converts AI text analysis to speech bytes for Streamlit."""
    response = client.audio.speech.create(
        model="tts-1",
        voice="nova", # Professional 'Siri-like' voice
        input=text[:4000] # Limit to avoid API errors
    )
    return response.content
