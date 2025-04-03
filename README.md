# hardened-catbox-scraper

Catbox Scraper with added security features, malicious / harmful file detection and isolation as well as sandboxing and proxy support to allow safer content retreival while protecting the end user. Full documentation will be fleshed out in the coming days. If there are any suggestions or additional functionality that you would like to see added let me know. No guarantees but I do try to iterate and improve on things over time and will consider any additional enhancements submitted if they make sense and do not incur a heavy overhead cost.

## Attribution
This project is a modified version of [Catbox Scraper ](https://github.com/dootss/catbox-scraper/blob/main/LICENSE) by [DOOTSS], licensed under the MIT License. DOOTSS's implementation is much faster than this one due to the extra overhead and if you are looking for the fastest possible throughput then that is the one to go with.

###Enhancements Added

    Advanced security features (signature detection, entropy analysis)
    Header analysis for detecting polyglot files
    Entropy-based detection of obfuscated content
    Certificate pinning for secure connections
    Asynchronous security processing
    Stenography detection
    Optional unblob integration for detecting files that could be malicious
    Isolation of files into sub folders if they are suspected to be malicious
    Install wrapper to create a conda environment for the requirements since some of the packages are older and can cause difficulty to those unfamiliar with python dependcency management. If you wish you may swap it out for your virtual environment of choice. I may update the script and add options for venv, pipx, and uv in the future.

### Possible future enhancements

    Blacklist implementation
    The ability to collect an array of known links that have files of a given type and return them as opposed to the file itself.
    Additional Security hardening using containerization and sandboxing to verify safety of obtained files.
    More robust logging functionality
    Process Isolation
    Multi Modal LLM support to scan and sort retrieved files by content type to allow the user to better filter files to the specific content they are searching for.

## Disclamer

This tool is a scraper that pulls content from an anon file hosting service and while many of the files are safe and contain helpful, funny, content / resources / shitposts for all kinds communities and interests a portion of the files hosted will be malicious or contain harmful content that should be handled appropriately. I have included features in this version to assist with isolating those files without imposing a hard filter because I realize that there are some that want to pull down and analyse malware for their own projects and am leaving it to the users descretion to utilize this script in accordance to their local laws and regulations. Please take appropriate measures to protect your system and yourself while using this and propery dispose of any malicious or harmful files. I am looking into a user controlled blacklist function but those are not 100% effective nor is any other safety measure. Please review the code in the script ahead of running it and understand what it does and does not do ahead of just hitting execute, this is true of anything pulled down from the internet and will save you headaches down the road. Getting off the soapbox but kinda wish my 10yo self back in the day had a heads up on some of this stuff ahead typing execute, pozzing my home pc, and getting banned from accessing it for the entire summer.

I am not responsible for the content uploaded to catbox or the content downloaded by this scraper. I am not responsible for any damage to your pc, soul, or person by any files that are opened after being retrieved via this scraper. I am not responsilbe for any failure in security protocol and you should understand what this script does and does not do. I am not responsible for any outcome resulting from the use of this script or the data retreived from this script.

False positives will occur, if the measures I have implemented result in a suspected false positive please use tools on your end to verify and do not send the false positive to me as I will not be able to fix it. I am using third party tools that I am familiar and have added the addtional features in such a way that it is easy to switch them out for your own tools. Know of an awesome tool that solves any gaps, please let me know about that and I will add it to the possible future enhancements section.
