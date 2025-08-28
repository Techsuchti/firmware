<img align="center" markdown="1" src=".github/meshtastic_logo.png" alt="Meshtastic Logo" width="80" />

# Meshtastic Firmware

![GitHub release downloads](https://img.shields.io/github/downloads/meshtastic/firmware/total) [![CI](https://img.shields.io/github/actions/workflow/status/meshtastic/firmware/main_matrix.yml?branch=master&label=actions&logo=github&color=yellow)](https://github.com/meshtastic/firmware/actions/workflows/ci.yml) [![CLA assistant](https://cla-assistant.io/readme/badge/meshtastic/firmware)](https://cla-assistant.io/meshtastic/firmware) [![Fiscal Contributors](https://opencollective.com/meshtastic/tiers/badge.svg?label=Fiscal%20Contributors&color=deeppink)](https://opencollective.com/meshtastic/) [![Vercel](https://img.shields.io/static/v1?label=Powered%20by&message=Vercel&style=flat&logo=vercel&color=000000)](https://vercel.com?utm_source=meshtastic&utm_campaign=oss)

<a href="https://trendshift.io/repositories/5524" target="_blank"><img src="https://trendshift.io/api/badge/repositories/5524" alt="meshtastic%2Ffirmware | Trendshift" style="width: 250px; height: 55px;" width="250" height="55" /></a>

<div align="center">
	<a href="https://meshtastic.org">Website</a>
	-
	<a href="https://meshtastic.org/docs/">Documentation</a>
</div>

## Overview

This repository contains the official device firmware for Meshtastic, an open-source LoRa mesh networking project designed for long-range, low-power communication without relying on internet or cellular infrastructure. The firmware supports various hardware platforms, including ESP32, nRF52, RP2040/RP2350, and Linux-based devices.

Meshtastic enables text messaging, location sharing, and telemetry over a decentralized mesh network, making it ideal for outdoor adventures, emergency preparedness, and remote operations.

### Get Started

- 🔧 **[Building Instructions](https://meshtastic.org/docs/development/firmware/build)** – Learn how to compile the firmware from source.
- ⚡ **[Flashing Instructions](https://meshtastic.org/docs/getting-started/flashing-firmware/)** – Install or update the firmware on your device.

Join our community and help improve Meshtastic! 🚀

## Änderungen (August 2025):

Die wichtigsten Anpassungen in dieser Version:

- **Entfernung alter Verschlüsselungsverfahren**: Die bisherigen Verschlüsselungsmethoden AES, AES-CCM und CTR wurden vollständig entfernt
- **Ausschließliche Nutzung von XChaCha20-Poly1305**: Das Projekt verwendet nun ausschließlich die moderne XChaCha20-Poly1305 AEAD-Verschlüsselung für erhöhte Sicherheit und bessere Performance
- **CryptoEngine-Klasse überarbeitet**: Umfassende Anpassungen der CryptoEngine-Klasse zur Unterstützung des neuen Verschlüsselungsstandards
- **Bereinigung der Codebasis**: Entfernung alter Quellcodedateien und Legacy-Code zur Verbesserung der Wartbarkeit

## Stats

![Alt](https://repobeats.axiom.co/api/embed/8025e56c482ec63541593cc5bd322c19d5c0bdcf.svg "Repobeats analytics image")
