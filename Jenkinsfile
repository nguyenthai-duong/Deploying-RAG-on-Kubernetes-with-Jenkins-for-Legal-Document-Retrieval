pipeline {
    agent any

    environment{
        registry = 'nthaiduong83/rag-controller'
        registryCredential = 'dockerhub'
        imageTag = "v22.$BUILD_NUMBER"
    }

    stages {
        stage('Build and Push') {
            steps {
                script {
                    echo 'Building image for deployment..'
                    def dockerImage = docker.build("${registry}:${imageTag}", "-f ./rag_controller1/Dockerfile ./rag_controller1")
                    echo 'Pushing image to dockerhub..'
                    docker.withRegistry( '', registryCredential ) {
                        dockerImage.push()
                    }
                }
            }
        }

        stage('Deploy') {
            agent {
                kubernetes {
                    containerTemplate {
                        name 'helm' // Name of the container to be used for helm upgrade
                        image 'nthaiduong83/jenkins-k8s:v1' // The image containing helm
                        alwaysPullImage true // Always pull image in case of using the same tag
                    }
                }
            }
            steps {
                script {
                    container('helm') {
                        sh("helm upgrade --install rag-controller ./rag_controller1/helm_rag_controller --namespace rag-controller --set deployment.image.name=${registry} --set deployment.image.version=${imageTag}")
                    }
                }
            }
        }
    }
}
