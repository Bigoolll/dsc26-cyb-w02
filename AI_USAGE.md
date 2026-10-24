# AI usage: dsc26-cyb-w02

## Tools

I used ChatGPT to help implement and debug the Python threat-model checker, understand the task requirements, and create the missing threat entries in the YAML model. I used the terminal, pytest, and the checker CLI to run the code and verify the results.

## What AI got wrong

An earlier attempt to add the new threats placed them under the wrong YAML section, which caused the model to fail when the checker tried to access the threats list. I noticed the problem from the YAML counts and the `KeyError: 'threats'` message, restored the original model, and used a Python script to add the threats to the correct section.

## In my own words

1. Why does a data store have no Spoofing threats in STRIDE per element, and where does that threat go instead?
A data store stores data, but it doesn't have an identity that can be impersonated. Spoofing usually applies to an external entity, like an attacker pretending to be a legitimate user, or a process using a fake identity to access the system.

2. Which of your eleven new threats would you fix first, and why that one?
I would fix T33 — unauthorized database writes first because an attacker could change case statuses or investigation results. That could lead to incorrect decisions about customer cases and make the payment system less trustworthy. I would prioritize preventing unauthorized writes through strict access controls and proper authorization checks.