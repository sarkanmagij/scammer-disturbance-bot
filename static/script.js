document.addEventListener('DOMContentLoaded', () => {
    const phoneNumberInput = document.getElementById('phoneNumber');
    const languageSelector = document.getElementById('languageSelector');
    const sendMessageBtn = document.getElementById('sendMessageBtn');
    const statusMessageDiv = document.getElementById('statusMessage');

    // New scheduler inputs
    const numMessagesInput = document.getElementById('numMessages');
    // Scheduler specific elements
    const scheduleToggle = document.getElementById('scheduleToggle');
    const schedulerSpecificOptions = document.getElementById('schedulerSpecificOptions');
    const numDaysInput = document.getElementById('numDays');
    const sendTimeInput = document.getElementById('sendTime');

    const updateSchedulerVisibility = () => {
        if (scheduleToggle.checked) {
            schedulerSpecificOptions.style.display = 'flex'; // Use 'flex' as it's a flex container
            sendMessageBtn.textContent = 'Schedule Messages';
        } else {
            schedulerSpecificOptions.style.display = 'none';
            sendMessageBtn.textContent = 'Send Now';
            // Optional: Reset scheduler fields when hiding them
            // numDaysInput.value = '1'; 
            // sendTimeInput.value = '';
        }
    };

    if(scheduleToggle) { // Ensure toggle exists before adding listener
        scheduleToggle.addEventListener('change', updateSchedulerVisibility);
        updateSchedulerVisibility(); // Initial call to set state
    }

    sendMessageBtn.addEventListener('click', async () => {
        const phoneNumber = phoneNumberInput.value;
        const selectedLanguage = languageSelector.value;
        const numMessages = numMessagesInput.value; 

        let numDaysValue = '1';
        let sendTimeValue = '';

        if (scheduleToggle && scheduleToggle.checked) {
            numDaysValue = numDaysInput.value;
            sendTimeValue = sendTimeInput.value;
        }

        if (!phoneNumber) {
            statusMessageDiv.textContent = 'Please enter a phone number.';
            statusMessageDiv.className = 'statusMessage error';
            return;
        }

        if (!/^\+?[1-9]\d{1,14}$/.test(phoneNumber)) {
            statusMessageDiv.textContent = 'Please enter a valid phone number (e.g., +12345678900).';
            statusMessageDiv.className = 'statusMessage error';
            return;
        }

        if (parseInt(numMessages, 10) < 1) {
            statusMessageDiv.textContent = 'Number of messages must be at least 1.';
            statusMessageDiv.className = 'statusMessage error';
            return;
        }

        if (scheduleToggle && scheduleToggle.checked) {
            if (parseInt(numDaysValue, 10) < 1) {
                statusMessageDiv.textContent = 'Number of days must be at least 1 for scheduling.';
                statusMessageDiv.className = 'statusMessage error';
                return;
            }
            if (!sendTimeValue) {
                statusMessageDiv.textContent = 'Please specify the time for scheduled messages.';
                statusMessageDiv.className = 'statusMessage error';
                return;
            }
        }

        statusMessageDiv.textContent = scheduleToggle.checked ? 'Scheduling messages...' : 'Sending message(s)...';
        statusMessageDiv.className = 'statusMessage';
        sendMessageBtn.disabled = true;

        try {
            const requestBody = {
                phone_number: phoneNumber,
                language: selectedLanguage,
                num_messages: parseInt(numMessages, 10),
                num_days: parseInt(numDaysValue, 10),
                send_time: sendTimeValue 
            };

            const response = await fetch('/send_sms', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody),
            });

            const result = await response.json();

            if (response.ok) {
                statusMessageDiv.textContent = result.message || (scheduleToggle.checked ? 'Messages scheduled successfully!' : 'Message(s) sent successfully!');
                statusMessageDiv.className = 'statusMessage success';
                phoneNumberInput.value = ''; 
                // numMessagesInput.value = '1';
                // if (scheduleToggle && scheduleToggle.checked) {
                //    numDaysInput.value = '1';
                //    sendTimeInput.value = '';
                //    scheduleToggle.checked = false; // Optionally uncheck
                //    updateSchedulerVisibility(); // Refresh UI
                // }
            } else {
                statusMessageDiv.textContent = result.error || 'Failed to process request.';
                statusMessageDiv.className = 'statusMessage error';
            }
        } catch (error) {
            console.error('Error processing request:', error);
            statusMessageDiv.textContent = 'An error occurred. Please try again.';
            statusMessageDiv.className = 'statusMessage error';
        } finally {
            sendMessageBtn.disabled = false;
        }
    });
}); 