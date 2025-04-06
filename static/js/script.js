document.addEventListener('DOMContentLoaded', function () {
    const container = document.querySelector('.card-preview-container');
    const bgImage = document.querySelector('.card-preview-bg');
    const textElement = document.createElement('div');
    const frontTextInput = document.getElementById('front_text');
    const colorInput = document.getElementById('color');
    const fontSelect = document.getElementById('font');
    const posXInput = document.getElementById('pos_x');
    const posYInput = document.getElementById('pos_y');
    const sendBtn = document.getElementById('send-btn');
    const backgroundSelect = document.getElementById('background');

    // Создаем текстовый элемент с фиксированным размером 24px
    textElement.className = 'draggable-text';
    textElement.textContent = '';
    textElement.style.fontSize = '24px'; // Фиксированный размер
    container.appendChild(textElement);

    // Инициализация
    updateTextContent();
    updateTextStyle();
    updateTextPosition();

    // Обработчики событий
    frontTextInput.addEventListener('input', updateTextContent);
    colorInput.addEventListener('input', updateTextStyle);
    fontSelect.addEventListener('change', updateTextStyle);
    posXInput.addEventListener('input', updatePositionFromInputs);
    posYInput.addEventListener('input', updatePositionFromInputs);
    backgroundSelect.addEventListener('change', updateBackground);
    sendBtn.addEventListener('click', sendPostcard);

    textElement.addEventListener('mousedown', startDrag);

    function updateTextContent() {
        textElement.textContent = frontTextInput.value || '';
    }

    function updateTextStyle() {
        textElement.style.color = colorInput.value;
        textElement.style.fontFamily = fontSelect.value;
        // Размер шрифта больше не изменяется
    }

    function updatePositionFromInputs() {
        updateTextPosition();
    }

    function updateTextPosition() {
        const bgRect = bgImage.getBoundingClientRect();
        const containerRect = container.getBoundingClientRect();

        // Рассчитываем относительные координаты
        const relX = parseInt(posXInput.value) || 0;
        const relY = parseInt(posYInput.value) || 0;

        // Позиционируем текст
        textElement.style.left = `${relX}px`;
        textElement.style.top = `${relY}px`;
    }

    function startDrag(e) {
        e.preventDefault();
        const startX = e.clientX;
        const startY = e.clientY;
        const startLeft = parseInt(textElement.style.left) || 0;
        const startTop = parseInt(textElement.style.top) || 0;

        function moveText(e) {
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;

            const newX = startLeft + dx;
            const newY = startTop + dy;

            textElement.style.left = `${newX}px`;
            textElement.style.top = `${newY}px`;

            posXInput.value = newX;
            posYInput.value = newY;
        }

        function stopDrag() {
            document.removeEventListener('mousemove', moveText);
            document.removeEventListener('mouseup', stopDrag);
        }

        document.addEventListener('mousemove', moveText);
        document.addEventListener('mouseup', stopDrag);
    }

    function updateBackground() {
        bgImage.src = `/static/images/backgrounds/${this.value}`;
    }

    function sendPostcard() {
        const form = document.getElementById('card-form');
        // Добавляем фиксированный размер шрифта в форму перед отправкой
        const fontSizeInput = document.createElement('input');
        fontSizeInput.type = 'hidden';
        fontSizeInput.name = 'font_size';
        fontSizeInput.value = '24';
        form.appendChild(fontSizeInput);

        form.submit();
    }
});