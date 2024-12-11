using System.Buffers.Binary;
using Lansweeper.Smb.Netbios.Enums;

namespace Lansweeper.Smb.Netbios;

/// <summary>
///     [RFC 1002] 4.3.1. SESSION PACKET
///     [MS-SMB2] 2.1 Transport - Direct TCP transport packet
/// </summary>
/// <remarks>
///     We extend this implementation to support Direct TCP transport packet which utilize the unused session packet flags
///     to extend the maximum trailer length.
/// </remarks>
public abstract class SessionPacket
{
    public const int HeaderLength = 4;
    public const int MaxSessionPacketLength = 131075;
    public const int MaxDirectTcpPacketLength = 16777215;

    public SessionPacketTypeName Type { get; protected set; }

    private byte[]? _trailer;
    public byte[] Trailer
    {
        get
        {
            if (_trailer is null) // Lazy initialization, often the trailer is not needed
            {
                _trailer = CreateTrailer();
            }
            return _trailer;
        }
        protected set { _trailer = value; }
    }

    /// <summary>
    /// does not set the <see cref="Trailer"/> and <see cref="TrailerLength"/> properties
    /// </summary>
    protected SessionPacket() { }

    protected SessionPacket(ReadOnlySpan<byte> buffer)
    {
        Type = (SessionPacketTypeName)buffer[0];
        var trailerLength = GetTrailerLength(buffer);
        Trailer = buffer.Slice(4, trailerLength).ToArray();
    }

    public virtual int Length => HeaderLength + Trailer.Length;

    /// <summary>
    /// Serializes the session packet to a byte array
    /// </summary>
    /// <remarks>
    /// Will set the <see cref="TrailerLength"/> property based on the length of the <see cref="Trailer"/> property
    /// </remarks>
    public virtual byte[] GetBytes()
    {
        var trailerLength = Trailer.Length;

        var buffer = new byte[HeaderLength + trailerLength];
        buffer[0] = (byte)Type;
        buffer[1] = (byte)(trailerLength >> 16);
        buffer[2] = (byte)(trailerLength >> 8);
        buffer[3] = (byte)trailerLength;
        Array.Copy(Trailer, 0, buffer, 4, trailerLength);

        return buffer;
    }

    /// <summary>
    /// Creates the trailer based on the properties of the session packet
    /// </summary>
    protected abstract byte[] CreateTrailer();

    public static int GetSessionPacketLength(ReadOnlySpan<byte> buffer)
    {
        int trailerLength = GetTrailerLength(buffer);
        return HeaderLength + trailerLength;
    }

    // Session packet: 17 bits (last bit of flags is also used)
    // Direct TCP transport packet: 3 bytes
    private static int GetTrailerLength(ReadOnlySpan<byte> buffer)
    {
        // length is located in bytes 1-3
        return (buffer[1] << 16) | BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2));
    }

    public static SessionPacket GetSessionPacket(ReadOnlySpan<byte> buffer)
    {
        var type = (SessionPacketTypeName)buffer[0];
        return type switch
        {
            SessionPacketTypeName.SessionMessage => new SessionMessagePacket(buffer),
            SessionPacketTypeName.SessionRequest => new SessionRequestPacket(buffer),
            SessionPacketTypeName.PositiveSessionResponse => new PositiveSessionResponsePacket(buffer),
            SessionPacketTypeName.NegativeSessionResponse => new NegativeSessionResponsePacket(buffer),
            SessionPacketTypeName.RetargetSessionResponse => new SessionRetargetResponsePacket(buffer),
            SessionPacketTypeName.SessionKeepAlive => new SessionKeepAlivePacket(buffer),
            _ => throw new InvalidDataException($"Invalid NetBIOS session packet type: 0x{(byte)type:X2}"),
        };
    }
}