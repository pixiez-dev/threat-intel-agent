# app.py

import sys
import os
from agent.agent_executor import run_agent


def chat():

    print("\n🛡️ SOC Threat Intelligence Agent")
    print("Type 'exit' to quit\n")

    while True:

        user_input = input("Analyst > ")

        if user_input.lower() in ["exit", "quit"]:
            break

        response = run_agent(user_input)

        print("\nAgent > ", response)
        print("-" * 60)


if __name__ == "__main__":
    chat()