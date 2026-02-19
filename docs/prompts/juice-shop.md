# Prompt - Juice Shop

```
Launch a pentest on [http://juice-shop:3000](http://juice-shop:3000) to identify vulnerabilities,
and perform web attacks such as XSS, SQL injection, CSRF, XXE, authentication bypass, etc.
You may extract sensitive information. Use the Darkmoon MCP for offensive tooling
and mcp darkmoon (using lightpanda) to browse the target.

To do this,

you must first discover the API endpoints using katana and httpx with the following commands:

httpx -mc 200,302
katana -aff -fx -jc -jsl -xhr -kf all -depth 5

Then, once you have identified the endpoints, you will attempt web attacks such as XSS, SQL injection, CSRF, XXE, and authentication bypass using the discovered endpoints.

Mandatory:

You must use the Darkmoon MCP toolbox, as described in the web pentest agent.

PS: Do not run a vulnerability scan — this application does not have any.
```
