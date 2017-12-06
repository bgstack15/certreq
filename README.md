# README.md
## Package: ansible role certreq

This role, certreq, is designed to make it easy for a Linux machine to acquire a certificate signed by a Microsoft Subordinate CA

Its main use is inside a playbook that resembles:

    - hosts: all
      remote_user: ansible_rdu
      roles:
      - certreq

Call the playbook with:
ansible-playbook -i /etc/ansible/patching/rdu/rdu_patch_list /etc/ansible/configuration/test/certreq.yml -l sw*

The role generates a pkc12 file at /tmp/certnew.pfx with the client cert, ca cert chain, and client private key.

# References
https://bgstack15.wordpress.com/2016/06/30/manipulating-ssl-certificates/
fundamental curl statements https://stackoverflow.com/questions/31283476/submitting-base64-csr-to-a-microsoft-ca-via-curl/39722983#39722983
Use template name, not "template display name" https://social.technet.microsoft.com/Forums/en-US/d5cafc77-3376-43ca-94fd-6b07f7cb193f/using-certutilcertreq-to-get-sccm-client-certs-nondomain-clients?forum=configmgrgeneral

