# sigma-rules

## ⚡ Supports
* Prefetch (LOLBAS)

## 🛡️ Purpose

This repository houses a collection of Sigma rules meticulously crafted for use with Velociraptor. These rules are designed to empower security professionals in:

* **🔍 Triage:** Quickly assessing and prioritizing potential security incidents.
* **🕵️‍♂️ Scanning:** Proactively identifying known malicious or suspicious activities within systems.

The goal is to provide a practical resource for leveraging Sigma's powerful detection capabilities within the Velociraptor framework.

## 📝 Sigma Rule Specifications

Each rule in this repository adheres to the following specifications:

* **Category:** (e.g., `execution`, `network`, `file_access`)

* **Product:** `windows`, `linux`, `Solaris`, etc.

* **Service:** (e.g., `prefetch`, `UserAssist`, `UAL`) 

**Example:**

```yaml
category: execution
product: windows
service: prefetch
```

## 📚 Resources

- [SigmaHQ](https://github.com/SigmaHQ/sigma)
- [Sigma rule spec](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md#logsource)
- [Velociraptor - Developing Sigma rules in Velociraptor](https://docs.velociraptor.app/blog/2025/2025-02-02-sigma/)
- [Velociraptor - Sigma in Velociraptor](https://sigma.velocidex.com/docs/sigma_in_velociraptor/)
- [Velociraptor - Sigma Windows Base Artifact](https://github.com/Velocidex/velociraptor-sigma-rules/blob/79bcffe6dd368c2ac0f867810a78e6d7e81359e1/config/windows_base.yaml#L1158)



# 🚀 Getting Started

.. placeholder ...

# 🤝 Contributing

We welcome contributions! Please submit pull requests for new rules, improvements to existing rules, or documentation updates.
