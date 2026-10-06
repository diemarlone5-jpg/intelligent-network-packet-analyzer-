import sys
import os

# Ajoute le dossier racine au path Python
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import streamlit as st
import json
import pandas as pd

try:
    from backend.sniffer import NetworkSniffer
    from backend.explainer import explain_packet, group_communications
except ImportError:
    from backend.main import NetworkAnalyzerCore
