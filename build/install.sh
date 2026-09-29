#!/bin/bash

binaries=(
    "inkmail"
    "inkmaild"
)

for file in "${binaries[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "Error: Required file '$file' is missing. Exiting..." >&2
        exit 1
    fi
done

echo "You may be prompted for your sudo password for system-wide installation."
sudo echo "Installing FtR InkMail..."

if [[ -f "/usr/local/bin/inkmail" ]]; then
    echo "File /usr/local/bin/inkmail exists already. Renaming with .old..."
    sudo mv "/usr/local/bin/inkmail" "/usr/local/bin/inkmail.old"
fi

if [[ -f "/usr/local/bin/inkmaild" ]]; then
    echo "File /usr/local/bin/inkmaild exists already. Renaming with .old..."
    sudo mv "/usr/local/bin/inkmaild" "/usr/local/bin/inkmaild.old"
fi

sudo install -m 0755 inkmaild /usr/local/bin/inkmaild
sudo install -m 0755 inkmail /usr/local/bin/inkmail

echo "Binaries copied successfully."

while true; do
    read -p "Should InkMailD start automatically? (Y/n): " bootresp
    case $bootresp in
        [Nn]* ) echo "Install finished! Run inkmaild and inkmail to start."; exit 0;;
        * ) break;;
    esac
done

while true; do
    read -p "Should this service restart automatically on failure? (Y/n): " restartresp
    case $restartresp in
        [Nn]* ) RESTART_POLICY="no"; break;;
        * ) RESTART_POLICY="on-failure"; break;;
    esac
done

while true; do
    read -p "Enter a port number to assign InkMailD to: " portnum

    if [[ "$portnum" =~ ^[0-9]+$ ]] && [ "$portnum" -ge 1024 ] && [ "$portnum" -le 65535]; then
        PORT_NUM="$portnum"
        break
    else
        echo "Invalid port number. Please enter an integer between 1024 and 65535."
    fi
done

while true; do
    read -r -p "Enter your username for InkMailD: " username

    if [[ "$username" =~ [[:space:]] ]]; then
        echo "Error: No whitespace allowed. Try again."
    elif [[ -z "$username" ]]; then
        echo "Input cannot be empty. Try again."
    else
        USERNAME="$username"
        break
    fi
done

SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/start-inkmaild.service"

mkdir -p "$SERVICE_DIR"

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Start InkMailD automatically along with user session

[Service]
Type=simple
ExecStart=/usr/local/bin/inkmaild -port $PORT_NUM -user "$USERNAME"
Restart=$RESTART_POLICY
RestartSec=10s

[Install]
WantedBy=default.target
EOF

echo "Reloading user daemons..."
systemctl --user daemon-reload
systemctl --user enable --now start-inkmaild.service

echo "InkMailD systemd service was created and started."

echo "InkMail installation complete!"
