from langchain.llms import Ollama
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import json
import re
from app.utils.logging import logger

llm = Ollama(model="llama3", base_url="http://192.168.0.90:11434", temperature=0.3)

# Updated prompt: no patches/mitigations, no visibility_score
prompt_template = PromptTemplate.from_template("""
You are a cybersecurity analyst.

You are provided a list of CVEs affecting a specific software and version. Each CVE includes a description and CVSS, exploit and impact scores. 
Your task is to generate a structured JSON summary with:
1. A vulnerability name and description.
2. A recommended technical **solution** (patch/fix).
3. A **mitigation** (temporary workaround or reduction strategy).
4. Additional metadata fields required to track both solution and mitigation.

Software Details:
- Name: {software_name}
- Version: {software_version}
- Vendor: {software_vendor}

Analyze only the CVEs relevant to this software and version.

Each CVE includes these fields:
- cve_id
- description
- cvssv3_base_score
- cvssv3_vector
- cwe_id
- affected_products
- references


Example:

Software Details:
- Name: Mozilla Firefox
- Version: 131.0.1
- Vendor: Mozilla

CVEs:
[
  {{
    "cve_id": "CVE-2023-XXXX",
    "description": "Memory corruption in rendering engine.",
    "cvssv3_base_score": 7.8,
    "cvssv3_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "cwe_id": "CWE-416",
    "affected_products": ["Firefox < 132"],
    "references": ["https://example.com/patch"]
  }}
]

Expected Output:
{{
  "name": "Memory Corruption in Firefox Rendering Engine",
  "description": "A memory corruption vulnerability in Firefox could allow an attacker to execute arbitrary code when a malicious web page is rendered.",
  "solution": {{
    "name": "Update to Firefox 132.0",
    "description": "Apply the security patch released by Mozilla to fix the rendering engine.",
    "references": ["https://example.com/patch"],
    "release_date": "2024-05-01",
    "type": "patch",
    "priority": "high",
    "rollback_available": "no"
  }},
  "mitigation": {{
    "name": "Disable JavaScript",
    "description": "Disable JavaScript temporarily to reduce attack vectors.",
    "references": [],
    "type": "configuration",
    "effectiveness": "moderate"
  }}
}}

### CVE List:
{cve_jsons}

Respond with **valid JSON only** using the following schema:

{{
  "name": "string",               // Concise vulnerability title
  "description": "string",        // Human-readable summary

  "solution": {{
    "name": "string",             // Name of the solution
    "description": "string",      // Technical fix
    "references": ["url", "..."], // List of URLs (if any)
    "release_date": "YYYY-MM-DD", // Approximate release date or null
    "type": "string",             // patch, update, hotfix, configuration, etc.
    "priority": "string",         // low, medium, high, critical
    "rollback_available": "yes" | "no"
  }},

  "mitigation": {{
    "name": "string",             // Name of the mitigation strategy
    "description": "string",      // Generic workaround or reduction guidance
    "references": ["url", "..."], // List of URLs (if any)
    "type": "string",             // e.g., firewall, configuration, awareness
    "effectiveness": "low" | "moderate" | "high"
  }}
}}

Instructions:
- Do not use the actual data given as example
- Use the software name/version/vendor to filter out irrelevant content.
- Use a **deduplicated title** for the "name" field. Use a short title covering the overall issue.
- For description, summarize all CVEs meaningfully.
- Do not fabricate references or release dates. Use null or an empty list when unsure.
- Use only ISO date format (`YYYY-MM-DD`) for release_date or null.
- Use technical and concise language.
- Output JSON only. No text or commentary outside the JSON.
""")

def get_vul_summary(cwe_id: str, software_name: str, software_version: str, software_vendor: str, cve_jsons: list[dict], group_id:str) -> dict:
    chain = LLMChain(llm=llm, prompt=prompt_template)
    formatted_json = json.dumps(cve_jsons, indent=2)
    result = chain.invoke({
        "software_name": software_name,
        "software_version": software_version,
        "software_vendor": software_vendor,
        "cve_jsons": formatted_json
    })
    return parse_result(result["text"])


def parse_result(text: str) -> dict:
    try:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:].strip()
        elif text.startswith("```"):
            text = text[3:].strip()
        if text.endswith("```"):
            text = text[:-3].strip()

        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            text = match.group(0).strip()

        parsed = json.loads(text)

        required_keys = {"name", "description", "solution", "mitigation"}
        if not required_keys.issubset(parsed):
            raise ValueError("Missing top-level fields in JSON")

        for subfield in ["name", "description", "references", "type"] + (
            ["release_date", "priority", "rollback_available"] if "solution" in parsed else []
        ):
            if subfield not in parsed["solution"]:
                raise ValueError(f"Missing field in solution: {subfield}")

        for subfield in ["name", "description", "references", "type", "effectiveness"]:
            if subfield not in parsed["mitigation"]:
                raise ValueError(f"Missing field in mitigation: {subfield}")

        return parsed

    except Exception as e:
        logger.info(f"[LLM WARNING] Failed to parse JSON:, {e}")
        logger.info(f"[RAW TEXT], {text[:500]}")
        return {
            "name": "Unknown",
            "description": f"LLM parsing error: {str(e)}",
            "solution": {
                "name": "Unknown",
                "description": "N/A",
                "references": [],
                "release_date": None,
                "type": "patch",
                "priority": "medium",
                "rollback_available": "no"
            },
            "mitigation": {
                "name": "Unknown",
                "description": "N/A",
                "references": [],
                "type": "configuration",
                "effectiveness": "moderate"
            }
        }