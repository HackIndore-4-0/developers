import { createContext, useContext, useState } from 'react'

const ApiContext = createContext()

export function ApiProvider({ children }) {
  const [apiKey, setApiKey] = useState(localStorage.getItem('dronikastra_api_key') || '1986ad8c0a5b3df4d7028d5f3c06e936c1f62c180195848babe8dcb07b070e89e')
  
  // Dynamic base URL setup configurable via Frontend Settings
  const [baseUrl, setBaseUrl] = useState(localStorage.getItem('dronikastra_base_url') || 'https://192.168.137.39:3443')

  const saveConfig = (key, url) => {
    // Strip trailing slashes to prevent API path issues (e.g. https://ip:3443/ becomes https://ip:3443)
    const cleanUrl = url.replace(/\/+$/, '');
    setApiKey(key)
    setBaseUrl(cleanUrl)
    localStorage.setItem('dronikastra_api_key', key)
    localStorage.setItem('dronikastra_base_url', cleanUrl)
  }

  return (
    <ApiContext.Provider value={{ apiKey, baseUrl, saveConfig }}>
      {children}
    </ApiContext.Provider>
  )
}

export function useApi() {
  return useContext(ApiContext)
}
