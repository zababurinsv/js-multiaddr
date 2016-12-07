node {
  stage('Build') {
		sh 'echo $PATH'
    sh 'npm install'
  }
  stage('Test') {
    sh 'npm run test:node'
  }
}
