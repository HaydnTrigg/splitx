#pragma once

template<typename T>
class c_buffer final
{
private:
    void* data = nullptr;

public:
    T* const get_data() const
    {
        return static_cast<T*>(data);
    }

    ~c_buffer()
    {
        free(data);
    }

    c_buffer(size_t size)
    {
        data = malloc(size);
        assert(data);
    }
};

template<typename T>
inline c_buffer<T> load_file_to_buffer(const char* file_path, const char open_type = '\0')
{
    char open_flags[] = { 'r', open_type, '\0' };
    FILE* fp;
    size_t file_size;
    size_t bytes_read;

    fp = fopen(file_path, open_flags);
    assert(fp);

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);

    fseek(fp, 0, SEEK_SET);
    c_buffer<T> buffer(file_size);

    bytes_read = fread(buffer.get_data(), file_size, 1, fp);
    assert(bytes_read = file_size);

    fclose(fp);

    return buffer;
}
