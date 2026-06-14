# app.py

import sys
from agent.agent_executor import run_agent
from security.prompt_guard import detect_injection  # 🛡️ Bring in security filter

def main():
    print("\n🛡️ SOC Threat Intelligence Agent")
    print("Type 'exit' to quit\n")
    
    while True:
        try:
            user_input = input("Analyst > ").strip()
            if not user_input:
                continue
            if user_input.lower() == 'exit':
                break
                
            # 🛡️ Apply Prompt Injection & Out-of-Scope Detection
            is_blocked, block_message = detect_injection(user_input)
            if is_blocked:
                print(f"\n⚠️ {block_message}\n")
                continue
            
            # If safe, forward to agent executor
            response = run_agent(user_input)
            print(f"\nAgent:\n{response}\n")
            
        except (KeyboardInterrupt, EOFError):
            break

if __name__ == "__main__":
    main()
