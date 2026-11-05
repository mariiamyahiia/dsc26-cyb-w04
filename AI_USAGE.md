# AI usage: dsc26-cyb-w04

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

i used Claude to understand the task, claude explained the requirements and gave me a general plan, i ran every command and test made every commit and pushed myself

## What AI got wrong

claude thought that tool output line numbers could be read without dealing with multiple tools having similar fingerprints or old suppressions, i saw when i ran pytest on the test suite that it was failing on situations, i changed the logic to properly check expiration dates against today and make sure tool matches are the same

## In my own words


1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?
fix DB_PASSWORD first, static analysis tools evaluate rules in isolation without understanding business or architectural context, bandit rates hardcoded strings based on heuristics while rating MD5 high simply because MD5 is a cryptographically weak hash. but in Diwans context an exposed production database password would be immediately targeted by an attacker making it the urgent vulnerability to remediate despite the tool’s low rating

2. Why does a suppression need an expiry date?
bec risk and context change over time but suppression remains unmonitored when the code is suppressed