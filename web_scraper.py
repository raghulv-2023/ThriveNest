import requests
from bs4 import BeautifulSoup
from googlesearch import search
import openai
from dotenv import load_dotenv
import os

# Load environment variables from key.env
load_dotenv(dotenv_path="key.env")
openai.api_key = os.getenv("OPENAI_API_KEY")


trusted_sites = ["mayoclinic.org", "webmd.com", "healthline.com", "clevelandclinic.org"]

def summarize_with_openai(text):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Summarize this medical advice in simple terms:\n\n{text}"}],
            temperature=0.5,
            max_tokens=300
        )
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"Summarization error: {e}"

def fetch_web_answer(query):
    try:
        print(f"Searching Google for: {query}")
        urls = list(search(query, num_results=10))

        for url in urls:
            if not any(site in url for site in trusted_sites):
                continue  # Only use trusted medical sources

            try:
                response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(response.text, 'html.parser')

                # Grab all text from main content areas
                paragraphs = soup.find_all('p')
                good_paragraphs = []

                for p in paragraphs:
                    text = p.get_text().strip()
                    if len(text) > 100 and any(word in text.lower() for word in query.lower().split()):
                        good_paragraphs.append(text)

                if good_paragraphs:
                    combined_text = " ".join(good_paragraphs[:3])  # take top 3 relevant chunks
                    return summarize_with_openai(combined_text)

            except Exception as e:
                print(f"Error scraping {url}: {e}")
                continue

        return "Sorry, I couldn't find a reliable medical explanation for that right now."

    except Exception as e:
        return f"Search error: {e}"
