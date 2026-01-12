from openai import OpenAI
import os
from rich.console import Console

console = Console()

class AIAnalyst:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            self.client = None
        else:
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )

    def analyze(self, results: list):
        if not self.client:
            return "❌ No API Key found. Please set `OPENROUTER_API_KEY` in `.env`."

        if not results:
            return "⚠️ No results to analyze."

        # Simplify results to save tokens
        simplified_results = []
        for r in results:
            simplified_results.append(f"{r['subdomain']} -> {r.get('ip_addresses', ['?'])[0]} ({r.get('cname', 'No CNAME')})")
        
        # Cap at 50 to avoid massive context if generic
        # If massive list, maybe just send the top interesting ones? 
        # For now, let's take first 50 and last 50 maybe?
        
        context_data = "\n".join(simplified_results[:100])
        
        prompt = f"""
        You are an elite Ethical Hacker and Cybersecurity Analyst.
        Analyze the following list of discovered subdomains for a target organization.
        
        Target Data:
        {context_data}
        
        Provide a Report in Markdown covering:
        1. **High-Value Targets**: Which subdomains look most interesting (admin, dev, test, api)?
        2. **Attack Surface**: Any potential misconfigurations based on names (e.g. S3 buckets, cloud services)?
        3. **Next Steps**: What specific checks should I run next (e.g. screenshotting, directory fuzzing)?
        
        Keep it concise, professional, and actionable.
        """

        try:
            response = self.client.chat.completions.create(
                model="google/gemini-2.0-flash-001", # Good balance of speed/cost
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                    {"role": "user", "content": prompt}
                ],
                # optional: extra_headers={"HTTP-Referer": "http://localhost", "X-Title": "SubEnum"}
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"❌ Error contacting AI: {str(e)}"
