ENTRY(alignstack)
SECTIONS
{
    .text :
    {
        *(.text.alignstack)
        *(.text.entrypoint)
    }
}