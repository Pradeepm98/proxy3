import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class ProxyServer(private val port: Int) {

    private val executor: ExecutorService = Executors.newCachedThreadPool()

    fun start() {
        val serverSocket = ServerSocket(port)
        println("Proxy server listening on port $port...")

        while (true) {
            val clientSocket = serverSocket.accept()
            executor.submit {
                handleClientRequest(clientSocket)
            }
        }
    }

    private fun handleClientRequest(clientSocket: Socket) {
        try {
            val request = readRequest(clientSocket)
            val host = getHostFromRequest(request)
            val remoteServerSocket = Socket(host, 80)

            // Forward request to remote server
            val remoteServerOutputStream = BufferedOutputStream(remoteServerSocket.getOutputStream())
            remoteServerOutputStream.write(request)
            remoteServerOutputStream.flush()

            // Forward response to client
            val clientOutputStream = BufferedOutputStream(clientSocket.getOutputStream())
            val remoteServerInputStream = BufferedInputStream(remoteServerSocket.getInputStream())

            val buffer = ByteArray(4096)
            var bytesRead: Int
            while (remoteServerInputStream.read(buffer).also { bytesRead = it } != -1) {
                clientOutputStream.write(buffer, 0, bytesRead)
                clientOutputStream.flush()
            }

            clientSocket.close()
            remoteServerSocket.close()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    private fun readRequest(clientSocket: Socket): ByteArray {
        val clientInputStream = BufferedInputStream(clientSocket.getInputStream())
        val requestBytes = clientInputStream.readBytes()
        return requestBytes
    }

    private fun getHostFromRequest(request: ByteArray): String {
        val requestString = String(request)
        val hostStartIndex = requestString.indexOf("Host: ") + 6
        val hostEndIndex = requestString.indexOf('\r', hostStartIndex)
        return requestString.substring(hostStartIndex, hostEndIndex)
    }
}

fun main() {
    val proxyServer = ProxyServer(12345)
    proxyServer.start()
}
