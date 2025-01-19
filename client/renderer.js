const information = document.getElementById('info')
information.innerText = `This app is using Chrome (v${versions.chrome()}), Node.js (v${versions.node()}), Electron (v${versions.electron()})`

const func = async () => {
  const response = await versions.ping()
  console.log(response)
}

func()