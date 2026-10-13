package proto

// PacketConn 是隧道的一个端点：一次读写一个 IP 包。
//
// 之所以把这个契约放在 proto 而不是 devtun：隧道逻辑（sshserver / sshclient）
// 只依赖它，不依赖 wireguard-go。好处是整条隧道链路可以用内存实现离线单测，
// 不需要 root、也不需要真实网卡——这对本项目尤其重要，因为创建 tun 必须 root。
type PacketConn interface {
	// ReadPacket 返回一个 IP 包的载荷。
	//
	// 返回的切片可能复用实现内部的缓冲，仅在下一次 ReadPacket 之前有效。
	// 调用方若要在下一次调用之后继续持有它，必须自行拷贝。
	// 该调用会阻塞，直到有包可读、对端关闭或出错。
	ReadPacket() ([]byte, error)

	// WritePacket 写出一个 IP 包。
	//
	// 实现不得在返回后继续持有 pkt 的底层数组；需要留存时必须拷贝。
	// 这样调用方可以放心复用写缓冲。
	WritePacket(pkt []byte) error

	// Close 关闭端点。重复调用应当是安全的。
	Close() error
}
