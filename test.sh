for file in /home/shuo/Throbber-private-/datasets/eTainter/annotated/bytecode/*.code; do
    cp "$file" "${file%.code}.hex"
done

/home/shuo/smartbugs-curated/dataset/denial_of_service

sudo ./smartbugs -t madmax -f /home/shuo/smartbugs-curated/full/*.hex --runtime --processes 48 --mem-limit 8g --timeout 1800