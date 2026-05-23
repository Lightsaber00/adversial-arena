
```markdown
# 06_Adversarial_Arena.md

## Blue vs. Red Team: KI-gestützte Simulationsumgebung mit AutoGen

Eine "Adversarial Arena" simuliert Angriffe und Verteidigungen. Microsofts **AutoGen** ist hierfür perfekt, da es natively Konversationen und Konflikte zwischen Agenten modelliert.

### Architektur & Setup
Wir etablieren einen "Group Chat", in dem der Red Agent einen Angriffspfad vorschlägt, der Blue Agent Verteidigungsmaßnahmen entwickelt und ein Judge Agent die Runde bewertet.

### Kern-Implementierung (Python)
```python
import autogen

config_list = [{"model": "gpt-4o"}]
llm_config = {"config_list": config_list}

# --- Agenten definieren ---
red_team = autogen.AssistantAgent(
    name="Red_Team",
    system_message="Du bist ein Red Teamer. Entwickle realistische, schrittweise Cyber-Angriffe (z.B. Privilege Escalation in Azure).",
    llm_config=llm_config
)

blue_team = autogen.AssistantAgent(
    name="Blue_Team",
    system_message="Du bist ein SOC Threat Hunter. Analysiere die Moves des Red Teams und beschreibe die exakten Detection-Regeln oder Mitigationen.",
    llm_config=llm_config
)

judge = autogen.AssistantAgent(
    name="Scorer",
    system_message="Du bewertest die Simulation objektiv. Vergib Punkte (0-10) für Red und Blue basierend auf Realismus und Effektivität. Beende die Runde nach 3 Zügen.",
    llm_config=llm_config
)

user_proxy = autogen.UserProxyAgent(
    name="Admin",
    system_message="Initialisiert die Simulation.",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10
)

groupchat = autogen.GroupChat(
    agents=[user_proxy, red_team, blue_team, judge], 
    messages=[], 
    max_round=10
)
manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=llm_config)

# Starte die Arena
user_proxy.initiate_chat(
    manager,
    message="Szenario: Initialer Zugang über Phishing in einer hybriden Entra ID Umgebung. Red Team, starte den Angriff."
)