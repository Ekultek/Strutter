# Strutter

Proof of Concept for CVE-2018-11776, comes complete with the ability to search Shodan API for targets

# CVE-2018-11776

> Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution 
when using results with no namespace and in same time, its upper action(s) have no or wildcard 
namespace. Same possibility when using url tag which doesn't have value and action set and in same time, 
its upper action(s) have no or wildcard namespace.

