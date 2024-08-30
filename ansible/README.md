add file key .json: service account -> create service acount -> add key
go to IAM and adding grant access with service_acount above, role: Compute Admin
conda create -n ansible python==3.9 -y
pip install -r requirements.txt

Create GCE with Ansible
gcloud auth application-default login
gcloud config set project jenkins1-433523
enable Compute Engine API

ansible-playbook playbooks/create_compute_instance.yaml
update ssh key in inventory

cat ~/.ssh/id_rsa.pub
update ssh keys in metadata of compute engine

ansible-playbook -i inventory playbooks/deploy_jenkins.yaml

Collect certificate K8s: kubectl config view --raw

kubectl create clusterrolebinding rag-controller-admin-binding \
  --clusterrole=admin \
  --serviceaccount=rag-controller:default \
  --namespace=rag-controller

kubectl create clusterrolebinding anonymous-admin-binding \
  --clusterrole=admin \
  --user=system:anonymous \
  --namespace=rag-controller