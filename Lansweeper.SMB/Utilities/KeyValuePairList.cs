namespace Lansweeper.Smb.Utilities;

public class KeyValuePairList<TKey, TValue> : List<KeyValuePair<TKey, TValue>>
{
    public KeyValuePairList()
    {
    }

    public KeyValuePairList(List<KeyValuePair<TKey, TValue>> collection) : base(collection)
    {
    }

    public List<TKey> Keys
    {
        get
        {
            var result = new List<TKey>();
            foreach (var entity in this) result.Add(entity.Key);
            return result;
        }
    }

    public List<TValue> Values
    {
        get
        {
            var result = new List<TValue>();
            foreach (var entity in this) result.Add(entity.Value);
            return result;
        }
    }

    public bool ContainsKey(TKey key)
    {
        return IndexOfKey(key) != -1;
    }

    public int IndexOfKey(TKey key)
    {
        for (var index = 0; index < Count; index++)
            if (this[index].Key!.Equals(key))
                return index;

        return -1;
    }

    public TValue? ValueOf(TKey key)
    {
        for (var index = 0; index < Count; index++)
            if (this[index].Key!.Equals(key))
                return this[index].Value;

        return default;
    }

    public void Add(TKey key, TValue value)
    {
        Add(new KeyValuePair<TKey, TValue>(key, value));
    }

    public new KeyValuePairList<TKey, TValue> GetRange(int index, int count)
    {
        return new KeyValuePairList<TKey, TValue>(base.GetRange(index, count));
    }
}