Threat Modeling AI Assistant based on https://github.com/mrwadams/stride-gpt as seen on https://stridegpt.streamlit.app/

To run the code:

streamlit run main.py

This code points to a Synopsys endpoint:
- must be run on Synopsys VPN
- must us a Synopsys OpenAI key

If you would like to run code against public openai endpoint, remove:

base_url="https://llm.labs.polaris.synopsys.com/v1"