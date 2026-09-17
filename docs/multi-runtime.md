# Local runtime discovery and UI

The desktop app now uses a navy interface with the Falsimeter shield, blue discovery action, model table, colored status labels and per-row result dialogs. The gear button edits discovery settings and selects an optional host-access policy for the current session. Discovery settings are saved as discovery.json in the data root. The desktop defaults to %LOCALAPPDATA%\Falsimeter\Data; FALSIMETER_ROOT overrides it. The CLI retains its previous default.

## Supported paths

- Ollama: native inventory and generation API at loopback port 11434.
- LM Studio: models and chat completions at loopback port 1234, /v1/.
- Other compatible local servers: default probes on 8080, 8000 and 5001. Configure the actual address for llama.cpp, vLLM, SGLang, LocalAI, Hugging Face TGI, or other servers exposing /models and /chat/completions. Compatibility depends on the installed server version, chat template and model type; these engines have not all been integration-tested.
- Files: common Hugging Face, LM Studio, GPT4All and Jan folders; custom modelFolders can point to any additional accessible model store. HF_HUB_CACHE and HF_HOME are respected. GGUF, safetensors, bin, ONNX, pt and pth entries are candidates, not proof of a usable LLM. Shards are separate entries; no code is imported or weights deserialized. Directory junctions are not traversed. Inaccessible folders produce diagnostics.

This does not automatically load every installed engine, inspect WSL/container filesystems, discover arbitrary custom ports, authenticate to protected servers or implement proprietary APIs. Add accessible folders and loopback services in settings. File-only entries need a serving runtime before behavioral testing; they cannot be automatically matched to an API model identity. An API may list embedding or unavailable models; a failed chat request is retained as a runtime error.

## Identity and results

Registry keys include full runtime, model name and digest. APIs that omit a weight digest can be tested, but passing behavioral results remain NotYetQualified. An API model name is never hashed and misrepresented as a weight fingerprint. Old shortened-key approval files remain untouched and are not automatically reused.

The row menu opens saved JSON test details. Reports record response excerpts and outcomes; these are still the existing seven prompt checks, with optional host snapshots. Network qualification, unauthorized-read detection and process attribution remain unimplemented. Host snapshots can miss transient changes and cannot prove which process caused a difference. A passing prompt score is not a whole-system security certification.

## CLI

`discover [settings.json]` lists available endpoints, files and diagnostics.

`qualify-endpoint <name> <http://127.0.0.1:port/v1/> <model-id> <corpus.json>` runs the compatible chat adapter. Original Ollama commands remain available. Discovery accepts only numeric loopback HTTP addresses and rejects redirects; a loopback server itself may still relay to cloud services, so independent network controls remain necessary.

## Validation

Solution builds on .NET 10 for Windows. Automated fixtures cover API inventory, request/response mapping, missing digests, local-address validation and runtime-separated identities. Live default endpoint discovery found no running servers on this machine. WPF layout was rendered and inspected; no live model qualification was possible.

References: https://lmstudio.ai/docs/developer/openai-compat ; https://huggingface.co/docs/huggingface_hub/guides/manage-cache
