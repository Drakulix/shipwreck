FROM scratch
COPY target/release/shipwreck /shipwreck
ENTRYPOINT [ "/shipwreck" ]
