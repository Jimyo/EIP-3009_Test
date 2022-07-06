function strip0x(v) {
    return v.replace(/^0x/, "");
}

function prepend0x(v) {
    return v.replace(/^(0x)?/, "0x");
}
