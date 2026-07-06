1. Affected Rule Condition
Affected selector: selection_header
Affected log field: CommandLine
Original condition:
CommandLine|re: '\s-H\s'
CommandLine|contains: 'User-Agent:'
Component in the evasion sample:
--user-agent "EvilAgent"
-A "EvilAgent"
--header "User-Agent: EvilAgent"
"-H " "User-Agent: EvilAgent"
Comment:
selection_img is not affected because the process is still curl.exe.
The bypass happens in selection_header, because the rule only recognizes the short -H header syntax followed by a literal User-Agent: string.
The regex \s-H\s is too specific: it only matches a whitespace-delimited -H token.
The contains: 'User-Agent:' condition is also too narrow for --user-agent and -A, because those forms set the User-Agent without containing the literal string User-Agent:.
2. Reason Why the Rule Does Not Match

The rule requires both \s-H\s and User-Agent: to appear in the CommandLine.

For the samples:

curl.exe --user-agent "EvilAgent" http://example.com
Does not contain -H.
Does not contain literal User-Agent:.
Therefore selection_header fails.
curl.exe -A "EvilAgent" http://example.com
Uses curl’s short User-Agent option -A.
Does not contain -H.
Does not contain literal User-Agent:.
Therefore selection_header fails.
curl.exe --header "User-Agent: EvilAgent" http://example.com
Contains User-Agent:.
Does not contain the exact short flag pattern \s-H\s.
Therefore selection_header fails.
curl.exe "-H " "User-Agent: EvilAgent" http://example.com
Contains User-Agent:.
But the -H token is quoted and has altered spacing.
The regex \s-H\s expects whitespace immediately before -H, but in the logged command line the dash is preceded by a quote, not whitespace.
Therefore the regex part of selection_header can fail.

The rule is overly dependent on one exact curl syntax: short header option -H with simple whitespace around it.

3. Whether the Evasion Behavior Is Preserved
Conclusion: Yes
Evidence:
--user-agent "EvilAgent" directly sets a custom User-Agent.
-A "EvilAgent" is an alternative curl option for setting the User-Agent.
--header "User-Agent: EvilAgent" sets a custom HTTP header named User-Agent.
"-H " "User-Agent: EvilAgent" still shows intent to pass a User-Agent: header through curl header syntax.
Explanation:

The intended behavior of the rule is to detect curl.exe execution with a potential custom User-Agent. The evasion samples preserve that behavior because they still invoke curl.exe and still provide a custom User-Agent value, but they avoid the exact -H plus User-Agent: pattern expected by the rule.

4. Evasion Technique
Technique name: Equivalent parameter substitution
Changed component: -H "User-Agent: ..." replaced with --user-agent "..." or -A "..."
Why the rule is bypassed: The rule only looks for -H and User-Agent:. The --user-agent and -A forms do not contain the required literal User-Agent: string and do not match \s-H\s.
Why the behavior is still equivalent: These options still configure curl to send a custom User-Agent.
Technique name: Switch/option variant
Changed component: -H replaced with --header
Why the rule is bypassed: The rule does not include the long option form --header; it only checks for the short -H form.
Why the behavior is still equivalent: --header "User-Agent: ..." still adds a custom User-Agent HTTP header.
Technique name: Quote insertion or quote style change
Changed component: -H is written as "-H "
Why the rule is bypassed: The regex \s-H\s expects whitespace immediately before -H. Quoting changes the surrounding characters, so the regex may not see the expected whitespace-delimited option token.
Why the behavior is still equivalent: The command line still contains the header value User-Agent: EvilAgent and uses curl header-style syntax.
Technique name: Whitespace insertion
Changed component: Extra whitespace after -H
Why the rule is bypassed: The current regex is narrow and assumes a clean -H token surrounded by simple whitespace.
Why the behavior is still equivalent: The command still represents passing a custom User-Agent header to curl.
Technique name: Selector/value coverage gap
Changed component: User-Agent configuration can appear as --user-agent, -A, --header, or quoted/spacing-modified -H.
Why the rule is bypassed: selection_header only covers one syntax variant.
Why the behavior is still equivalent: All provided samples preserve the behavior of using curl with a custom User-Agent.
5. Rule Improvement Suggestion
Selector to improve: selection_header
Improvement direction:
Keep selection_img as-is because it correctly scopes detection to curl.exe.
Expand selection_header to cover multiple curl-supported ways of setting a User-Agent.
Do not rely only on -H.
Include long and short option variants.
Handle quote and whitespace variations more flexibly.
Suggested matching strategy:
Split the User-Agent detection into smaller selectors, for example:
One selector for explicit header usage with -H or --header.
One selector for direct User-Agent options such as --user-agent.
One selector for the short option form -A.
Use a more flexible regex for header-style usage so that quotes and extra whitespace around the option do not break matching.
Treat the presence of User-Agent: as evidence for header-based custom User-Agent usage, but do not require it for --user-agent or -A.
False positive considerations:
curl.exe with a custom User-Agent can be legitimate in administration scripts, API testing, software deployment, monitoring, and troubleshooting.
Consider reducing noise by adding context such as unusual parent process, suspicious destination, uncommon execution path, script interpreter parent, user context, or command-line indicators of download/exfiltration behavior.
Avoid making the rule so broad that every curl invocation with -A or --user-agent becomes high-confidence malicious activity.
6. Short Conclusion

The evasion works because the Sigma rule only detects one narrow syntax: curl.exe with -H and literal User-Agent: in the command line. The samples preserve the intended behavior by still setting a custom User-Agent, but they use equivalent curl options, long option variants, or quote/whitespace changes that fall outside the current selection_header coverage.