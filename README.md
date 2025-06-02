# SafeSurf: Defender Against Darknet Threats
Authors: Mohammad Jihad Obaidat, Ibrahim Ahmad Al-Syouf, Yahia Faek Awawdeh, Anas Eid Masa’deh
Supervisor: Dr. Qasem Abu Al-Haija
Institution: Jordan University of Science and Technology (JUST)
Date: Jun 2025

# Overview
SafeSurf is an intelligent Intrusion Prevention System (IPS) designed to detect and block darknet-related threats in real-time using advanced supervised machine learning models. The system leverages a hierarchical classification approach to analyze network traffic and distinguish darknet types, behaviors, and threats with high accuracy and low latency.

# Project Objectives
Develop a multi-layered IPS using supervised learning.

Achieve high detection accuracy (95–99%) with low false positives.

Enable real-time threat response (within 100ms).

Support incremental learning to adapt to evolving darknet traffic.

# Key Features
Hierarchical Multi-Layered Classifier: Three classification layers:

Layer 1: Darknet vs. Normal traffic

Layer 2: Darknet type (Tor, I2P, VPN, ZeroNet, Freenet)

Layer 3: Behavior classification (e.g., browsing, chatting)

Real-Time IPS Engine: Automatically allows or blocks traffic based on classification and configurable rules.

Web Dashboard: Live traffic monitoring, user authentication, alerting, and reporting via a Flask-based UI.

Incremental Learning Support: Enables model adaptation without full retraining.

Dataset Creation: Includes real traffic captures from multiple darknet tools (Tor, I2P, VPN, etc.).

# Deliverables
Complete dataset labeled across three classification layers.

Python-based machine learning models (e.g., RF, XGB, MLP).

Real-time IPS engine integrated with NetfilterQueue.

Full-featured Flask web application.

System documentation, diagrams, and user manual.

# Technologies Used
Languages & Frameworks: Python, Flask, Scikit-learn

Tools: CICFlowMeter, Wireshark, Docker, Redis, NetfilterQueue

Databases: SQL (Auth), NoSQL (Logs, Rules)

Cloud: AWS (Email Alerts), Azure (Storage)

# Target Users
Network Admins & SOC Teams: For live darknet traffic detection and response.

Researchers & Analysts: To study darknet traffic patterns and behaviors.

Government & Healthcare: Enhance national cybersecurity and protect sensitive networks.

# Performance Highlights
98–99% accuracy in classification tasks.

Real-time performance with low latency.

Extensive testing with confusion matrices, ROC curves, and ensemble evaluations.

# License
This project is an academic prototype and currently not licensed for commercial use. For inquiries or collaboration, please contact the authors or supervisor.

# Contact
For more information or collaboration:

Dr. Qasem Abu Al-Haija (Supervisor) https://www.linkedin.com/in/qasem-abu-al-haija-190a123b/

Mohammad Obaidat: https://www.linkedin.com/in/mobaidat75/

Ibrahim Al-Syouf https://www.linkedin.com/in/ibrahim-al-syouf-145371308/

Anas Masa'deh: https://www.linkedin.com/in/anas-masadeh-58a212288/

Yahea Awawdeh  https://www.linkedin.com/in/yahea-awawdeh-039865295/


